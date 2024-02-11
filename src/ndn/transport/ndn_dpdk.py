# -----------------------------------------------------------------------------
# Copyright (C) 2019-2023 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import asyncio as aio
import logging
import aiohttp
import json
import abc
import typing
from .. import encoding as enc
from .prefix_registerer import PrefixRegisterer
from . import face


class GqlClient:
    def __init__(self, gqlserver: str):
        self.address = gqlserver

    async def _request(self, query: str, request: dict):
        async with aiohttp.ClientSession() as session:
            async with session.post(self.address, data=json.dumps({
                "query": query,
                "variables": request,
            })) as response:
                # add some error handling here, probably
                return await response.json()

    async def create_face(self, locator: dict) -> str:
        response = await self._request(
            "mutation createFace($locator: JSON!) { createFace(locator: $locator) { id }}",
            {"locator": locator})
        try:
            return response["data"]["createFace"]["id"]
        except (KeyError, IndexError):
            raise RuntimeError(json.dumps(response))

    async def insert_fib(self, face_id: str, prefix: str):
        response = await self._request(
            """mutation insertFibEntry($name: Name!, $nexthops: [ID!]!, $strategy: ID, $params: JSON) {
                    insertFibEntry(name: $name, nexthops: $nexthops, strategy: $strategy, params: $params) {
                        id
                    }
                }
            """, {"name": prefix, "nexthops": [face_id]})
        try:
            return response["data"]["insertFibEntry"]["id"]
        except (KeyError, IndexError):
            raise RuntimeError(json.dumps(response))

    async def delete(self, obj_id: str) -> bool:
        response = await self._request("mutation delete($id: ID!) {delete(id: $id)}",
                                       {"id": obj_id})
        try:
            return response["data"]["delete"]
        except (KeyError, IndexError):
            raise RuntimeError(json.dumps(response))


class NdnDpdkFace(face.Face, abc.ABC):
    face_id: str
    gql_url: str
    client: GqlClient

    def __init__(self, gql_url: str):
        super().__init__()
        self.gql_url = gql_url
        self.face_id = ""
        self.client = GqlClient(gql_url)

    async def isLocalFace(self):
        return False


class NdnDpdkUdpFace(NdnDpdkFace):
    self_addr: str
    self_port: int
    dpdk_addr: str
    dpdk_port: int

    class PacketHandler(aio.DatagramProtocol):
        def __init__(self,
                     callback: typing.Callable[[int, bytes], typing.Coroutine[any, None, None]],
                     close: aio.Future) -> None:
            super().__init__()
            self.callback = callback
            self.close = close
            self.transport = None

        def connection_made(self, transport: aio.DatagramTransport):
            self.transport = transport

        def datagram_received(self, data: bytes, _addr: tuple[str, int]):
            typ, _ = enc.parse_tl_num(data)
            aio.create_task(self.callback(typ, data))

        def send(self, data):
            self.transport.sendto(data)

        def error_received(self, exc: Exception):
            self.close.set_result(True)
            logging.getLogger(__name__).warning(exc)

        def connection_lost(self, exc):
            if not self.close.done():
                self.close.set_result(True)
            if exc:
                logging.getLogger(__name__).warning(exc)

        def shutdown(self):
            if self.transport is not None:
                self.transport.close()

    handler: typing.Optional[PacketHandler]

    def __init__(self, gql_url: str, self_addr: str, self_port: int,
                 dpdk_addr: str, dpdk_port: int):
        super().__init__(gql_url)
        self.self_addr = self_addr
        self.self_port = self_port
        self.dpdk_addr = dpdk_addr
        self.dpdk_port = dpdk_port
        self.handler = None

    async def open(self):
        # Start UDP listener
        loop = aio.get_running_loop()
        self.running = True
        self.handler = NdnDpdkUdpFace.PacketHandler(self.callback, loop.create_future())
        await loop.create_datagram_endpoint(
            lambda: self.handler,
            local_addr=(self.self_addr, self.self_port),
            remote_addr=(self.dpdk_addr, self.dpdk_port))

        # Send GraphQL command
        # TODO: IPv6 is not supported.
        self.face_id = await self.client.create_face({
            "scheme": "udp",
            "remote": f'{self.self_addr}:{self.self_port}',
            "local": f'{self.dpdk_addr}:{self.dpdk_port}',
        })

    def shutdown(self):
        if self.running:
            self.running = False

            # Send GraphQL command
            aio.create_task(self.client.delete(self.face_id))
            self.handler.shutdown()
            self.face_id = ""

    def send(self, data: bytes):
        if self.handler is not None:
            self.handler.send(data)
        else:
            raise RuntimeError('Unable to send packet before connection')

    async def run(self):
        if self.running:
            await self.handler.close
        else:
            raise RuntimeError('Unable to run a face before connection')


class DpdkRegisterer(PrefixRegisterer):
    face: NdnDpdkFace
    fib_entries: dict[str, str]

    def __init__(self, dpdk_face: NdnDpdkFace):
        super().__init__()
        self.face = dpdk_face
        self.fib_entries = {}

    async def register(self, name: enc.FormalName) -> bool:
        if not self.face.running:
            raise RuntimeError('Cannot register prefix when face is not running')
        client = self.face.client
        name_uri = enc.Name.to_canonical_uri(name)
        try:
            fib_id = await client.insert_fib(self.face.face_id, name_uri)
            self.fib_entries[name_uri] = fib_id
        except KeyError:
            return False
        return True

    async def unregister(self, name: enc.FormalName) -> bool:
        if not self.face.running:
            raise RuntimeError('Cannot unregister prefix when face is not running')
        client = self.face.client
        name_uri = enc.Name.to_canonical_uri(name)
        if name_uri not in self.fib_entries:
            return False
        fib_id = self.fib_entries[name_uri]
        try:
            await client.delete(fib_id)
        except KeyError:
            return False
        return True
