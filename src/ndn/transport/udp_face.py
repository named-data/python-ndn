# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
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
from typing import Tuple

from ..encoding.tlv_var import parse_tl_num
from .ip_face import IpFace


class UdpFace(IpFace):

    def __init__(self, host: str = '127.0.0.1', port: int = 6363):
        super().__init__()
        self.host = host
        self.port = port

    async def open(self):

        class PacketHandler:

            def __init__(self, callback, close) -> None:
                self.callback = callback
                self.close = close

            def connection_made(
                    self, transport: aio.DatagramTransport) -> None:
                self.transport = transport

            def datagram_received(
                    self, data: bytes, addr: Tuple[str, int]) -> None:
                typ, _ = parse_tl_num(data)
                aio.create_task(self.callback(typ, data))
                return

            def send(self, data):
                self.transport.sendto(data)

            def error_received(self, exc: Exception) -> None:
                self.close.set_result(True)
                logging.getLogger(__name__).warning(exc)

            def connection_lost(self, exc):
                if not self.close.done():
                    self.close.set_result(True)
                if exc:
                    logging.getLogger(__name__).warning(exc)

        loop = aio.get_running_loop()
        self.running = True
        close = loop.create_future()
        handler = PacketHandler(self.callback, close)
        transport, _ = await loop.create_datagram_endpoint(
            lambda: handler,
            remote_addr=(self.host, self.port))
        self.handler = handler
        self.transport = transport
        self.close = close

    async def run(self):
        await self.close

    def send(self, data: bytes):
        self.handler.send(data)

    def shutdown(self):
        self.running = False
        self.transport.close()
