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
import io
import abc
import asyncio as aio
import logging
from typing import Optional, Callable, Coroutine, Any
from ..encoding.tlv_var import read_tl_num_from_stream, parse_tl_num
from ..platform import Platform


class Face(metaclass=abc.ABCMeta):
    running: bool = False
    callback: Callable[[int, bytes], Coroutine[Any, None, None]] = None

    def __init__(self):
        self.running = False

    @abc.abstractmethod
    async def open(self):
        pass

    @abc.abstractmethod
    def shutdown(self):
        pass

    @abc.abstractmethod
    def send(self, data: bytes):
        pass

    @abc.abstractmethod
    async def run(self):
        pass


class StreamFace(Face, metaclass=abc.ABCMeta):
    reader: Optional[aio.StreamReader] = None
    writer: Optional[aio.StreamWriter] = None

    def shutdown(self):
        self.running = False
        if self.writer:
            self.writer.close()
            self.writer = None

    async def run(self):
        while self.running:
            try:
                bio = io.BytesIO()
                typ = await read_tl_num_from_stream(self.reader, bio)
                siz = await read_tl_num_from_stream(self.reader, bio)
                bio.write(await self.reader.readexactly(siz))
                buf = bio.getvalue()
                aio.create_task(self.callback(typ, buf))
            except (aio.IncompleteReadError, ConnectionResetError):
                self.shutdown()

    def send(self, data: bytes):
        self.writer.write(data)


class UnixFace(StreamFace):
    path: str = '/run/nfd.sock'

    def __init__(self, path: str = ''):
        super().__init__()
        if path:
            self.path = path

    async def open(self):
        self.reader, self.writer = await Platform().open_unix_connection(self.path)
        self.running = True


class TcpFace(StreamFace):
    host: str = '127.0.0.1'
    port: int = 6363

    def __init__(self, host: str = '', port: int = 0):
        super().__init__()
        if host:
            self.host = host
        if port:
            self.port = port

    async def open(self):
        self.reader, self.writer = await aio.open_connection(self.host, self.port)
        self.running = True


class UdpFace(Face):
    host: str = '127.0.0.1'
    port: int = 6363

    def __init__(self, host: str = '', port: int = 0):
        super().__init__()
        if host:
            self.host = host
        if port:
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
                    self, data: bytes, addr: tuple[str, int]) -> None:
                typ, _ = parse_tl_num(data)
                aio.create_task(self.callback(typ, data))
                return

            def send(self, data):
                self.transport.sendto(data)

            def error_received(self, exc: Exception) -> None:
                self.close.set_result(True)
                logging.warning(exc)

            def connection_lost(self, exc):
                if not self.close.done():
                    self.close.set_result(True)
                if exc:
                    logging.warning(exc)

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
