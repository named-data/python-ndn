import abc
import asyncio as aio
from typing import Optional, Callable, Coroutine, Any, Tuple
from ..encoding.tlv_var import read_tl_num_from_stream


class Face(metaclass=abc.ABCMeta):
    running: bool = False
    callback: Callable[[int, bytes], Coroutine[Any, None, None]]

    def __init__(self, callback):
        self.callback = callback
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

    def __init__(self, callback, path: str = ''):
        super().__init__(callback)
        if path:
            self.path = path

    async def open(self):
        self.reader, self.writer = await aio.open_unix_connection(self.path)
        self.running = True


class TcpFace(StreamFace):
    host: str
    port: int

    def __init__(self, callback, host: str, port: int):
        super().__init__(callback)
        self.host = host
        self.port = port

    async def open(self) -> Tuple[aio.StreamReader, aio.StreamWriter]:
        return await aio.open_connection(self.host, self.port)
