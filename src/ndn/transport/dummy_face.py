import asyncio as aio
from ndn.encoding import parse_tl_num
from ndn.transport.stream_socket import Face


class DummyFace(Face):
    def __init__(self, test_func, app):
        super().__init__(app._receive)
        self.output_buf = b''
        self.test_func = test_func
        self.event = aio.Event()
        self.app = app

    async def open(self):
        self.running = True

    def shutdown(self):
        self.running = False

    def send(self, data: bytes):
        self.output_buf += data
        self.event.set()

    async def run(self):
        await self.test_func(self)
        self.app.shutdown()

    async def consume_output(self, expected_output, timeout=0.01):
        await aio.wait_for(self.event.wait(), timeout)
        self.event.clear()
        assert self.output_buf == expected_output
        self.output_buf = b''

    async def input_packet(self, packet):
        packet = memoryview(packet)
        typ, typ_len = parse_tl_num(packet)
        siz, siz_len = parse_tl_num(packet, typ_len)
        offset = typ_len + siz_len
        assert len(packet) == offset + siz
        await self.callback(typ, packet[offset:])
