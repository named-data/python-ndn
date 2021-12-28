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

from ndn.encoding import parse_tl_num
from ndn.transport.face import Face


class DummyFace(Face):
    app = None

    def __init__(self, test_func):
        super().__init__()
        self.output_buf = b''
        self.test_func = test_func
        self.event = aio.Event()
        self.expected_len = 2 ** 32

    async def open(self):
        self.running = True

    def shutdown(self):
        self.running = False

    def send(self, data: bytes):
        self.output_buf += data
        if len(self.output_buf) >= self.expected_len:
            self.event.set()

    async def run(self):
        await self.test_func(self)
        if self.app:
            self.app.shutdown()

    def isLocalFace(self):
        return True

    async def consume_output(self, expected_output, timeout=0.01):
        self.expected_len = len(expected_output)
        if len(self.output_buf) < self.expected_len:
            await aio.wait_for(self.event.wait(), timeout)
        self.expected_len = 2 ** 32
        self.event.clear()
        assert self.output_buf == expected_output
        self.output_buf = b''

    async def ignore_output(self, length, timeout=0.1):
        self.expected_len = length
        await aio.wait_for(self.event.wait(), timeout)
        self.expected_len = 2 ** 32
        self.event.clear()
        self.output_buf = b''

    async def input_packet(self, packet):
        packet = memoryview(packet)
        typ, typ_len = parse_tl_num(packet)
        siz, siz_len = parse_tl_num(packet, typ_len)
        offset = typ_len + siz_len
        assert len(packet) == offset + siz
        await self.callback(typ, packet)
