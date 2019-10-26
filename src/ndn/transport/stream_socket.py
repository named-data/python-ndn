# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
import abc
import asyncio as aio
from typing import Optional, Callable, Coroutine, Any, Tuple
from ..encoding.tlv_var import read_tl_num_from_stream


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
                typ = await read_tl_num_from_stream(self.reader)
                siz = await read_tl_num_from_stream(self.reader)
                buf = await self.reader.readexactly(siz)
                aio.ensure_future(self.callback(typ, buf))
            except aio.IncompleteReadError:
                self.shutdown()

    def send(self, data: bytes):
        self.writer.write(data)


class UnixFace(StreamFace):
    path: str = '/var/run/nfd.sock'

    def __init__(self, path: str = ''):
        super().__init__()
        if path:
            self.path = path

    async def open(self):
        self.reader, self.writer = await aio.open_unix_connection(self.path)
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
