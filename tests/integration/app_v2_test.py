# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
import abc
import asyncio as aio
import pytest
from ndn import appv2 as app
from ndn import security as sec
from ndn import encoding as enc
from ndn import types
from ndn.transport.dummy_face import DummyFace


class NDNAppTestSuite:
    app = None
    signer = None

    def test_main(self):
        aio.run(self.comain())

    async def comain(self):
        face = DummyFace(self.face_proc)
        self.signer = sec.DigestSha256Signer()
        self.app = app.NDNApp(face)
        face.app = self.app
        await self.app.main_loop(self.app_main())

    @abc.abstractmethod
    async def face_proc(self, face: DummyFace):
        pass

    @abc.abstractmethod
    async def app_main(self):
        pass


class TestConsumerBasic(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x050\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                  b'\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x12\x00\x0c\x02\x17p')
        await face.input_packet(b'\x06B\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                b'\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8'
                                b'\x15\rHello, world!')

    async def app_main(self):
        name = '/example/testApp/randomData/t=1570430517101'
        data_name, content, pkt_context = await self.app.express(
            name, app.pass_all, must_be_fresh=True, can_be_prefix=False, lifetime=6000, nonce=None)
        assert data_name == enc.Name.from_str(name)
        assert pkt_context['meta_info'].freshness_period == 1000
        assert content == b'Hello, world!'


class TestInterestCancel(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x15\x07\x0f\x08\rnot important\x0c\x02\x0f\xa0')

    async def app_main(self):
        with pytest.raises(types.InterestCanceled):
            await self.app.express('not important', app.pass_all, nonce=None)


class TestInterestNack(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events'
                                  b'\x21\x00\x12\x00\x0c\x02\x03\xe8')
        await face.input_packet(b'\x64\x36\xfd\x03\x20\x05\xfd\x03\x21\x01\x96'
                                b'\x50\x2b\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events'
                                b'\x21\x00\x12\x00\x0c\x02\x03\xe8')

    async def app_main(self):
        with pytest.raises(types.InterestNack) as nack:
            await self.app.express('/localhost/nfd/faces/events', app.pass_all, nonce=None, lifetime=1000,
                                   must_be_fresh=True, can_be_prefix=True)
        assert nack.value.reason == 150


class TestInterestTimeout(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x14\x07\x0f\x08\rnot important\x0c\x01\x0a')
        await aio.sleep(0.05)

    async def app_main(self):
        with pytest.raises(types.InterestTimeout):
            await self.app.express('not important', app.pass_all, nonce=None, lifetime=10)


class TestDataValidationFalure(NDNAppTestSuite):
    @staticmethod
    async def validator(_name, _sig, _context) -> types.ValidResult:
        await aio.sleep(0.003)
        return types.ValidResult.FAIL

    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x1b\x07\x10\x08\x03not\x08\timportant\n\x04\x00\x00\x00\x00\x0c\x01\x05')
        await face.input_packet(b'\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test')

    async def app_main(self):
        with pytest.raises(types.ValidationFailure) as e:
            await self.app.express('/not/important', validator=self.validator, nonce=0, lifetime=5)
        assert e.value.name == enc.Name.from_str('/not/important')
        assert e.value.content == b'test'
        assert e.value.result == types.ValidResult.FAIL


class TestInterestCanBePrefix(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x0a\x07\x05\x08\x03not\x0c\x01\x05'
                                  b'\x05\x0c\x07\x05\x08\x03not\x21\x00\x0c\x01\x05'
                                  b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.input_packet(b'\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test')
        await aio.sleep(0.1)

    async def app_main(self):
        future1 = self.app.express('/not', app.pass_all, nonce=None, lifetime=5, can_be_prefix=False)
        future2 = self.app.express('/not', app.pass_all, nonce=None, lifetime=5, can_be_prefix=True)
        future3 = self.app.express('/not/important', app.pass_all, nonce=None, lifetime=5, can_be_prefix=False)
        name2, content2, _ = await future3
        name1, content1, _ = await future2
        with pytest.raises(types.InterestTimeout):
            await future1
        assert name1 == enc.Name.from_str('/not/important')
        assert content1 == b'test'
        assert name2 == enc.Name.from_str('/not/important')
        assert content2 == b'test'


class TestRoute(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.consume_output(b'\x06\x24\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test'
                                  b'\x16\x03\x1b\x01\xc8\x17\x00')

    async def app_main(self):
        @self.app.route('/not')
        def on_interest(name, _app_param, reply: app.ReplyFunc, _context):
            data = self.app.make_data(name, b'test', signer=sec.NullSigner())
            assert reply(data)


class TestInvalidInterest(NDNAppTestSuite):
    @staticmethod
    async def validator(_name, _sig, _context) -> types.ValidResult:
        await aio.sleep(0.003)
        return types.ValidResult.FAIL

    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x05`\x072\x08\x03not\x08\timportant'
                                b'\x02 E\x8a\xeaxI}[\xb1\xcd\xf0\x01\xbe'
                                b'\xdb\xe9\x03\x085\xb1g+K\xa8jK,\xd0\xad'
                                b')\x07\x83\x96\xbb\x0c\x01\x05$\x00,\x03'
                                b'\x1b\x01\x00. !\x93!zG[%\xcfs\xe89\\\x8f'
                                b'^\xd3\xa4\xb9\x13\xaa\x7f\xa6?\xd7\x13aVyS\xdc\x1dW\xea')
        await aio.sleep(0.005)

    async def app_main(self):
        @self.app.route('/not', validator=self.validator)
        def on_interest(_name, _app_param, _reply: app.ReplyFunc, _context):
            raise ValueError('This test fails')


class TestRoute2(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.consume_output(b'\x06\x24\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test'
                                  b'\x16\x03\x1b\x01\xc8\x17\x00')

    async def app_main(self):
        @self.app.route('/not')
        def on_interest(name, _app_param, reply: app.ReplyFunc, context):
            assert context['raw_packet'] == b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05'
            assert not context['sig_ptrs'].signature_info
            reply(self.app.make_data(name, b'test', signer=sec.NullSigner()))


class TestConsumerRawPacket(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x050\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                  b'\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x12\x00\x0c\x02\x17p')
        await face.input_packet(b'\x06B\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                b'\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8'
                                b'\x15\rHello, world!')

    async def app_main(self):
        name = '/example/testApp/randomData/t=1570430517101'
        _, _, pkt_context = await self.app.express(
            name, validator=app.pass_all,
            must_be_fresh=True, can_be_prefix=False, lifetime=6000, nonce=None, need_raw_packet=True)
        raw = pkt_context['raw_packet']
        assert (raw == b'\x06\x42\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                       b'\x38\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8'
                       b'\x15\rHello, world!')


class TestCongestionMark(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x64\x1e\xfd\x03\x40\x01\x01\x50\x17'
                                b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.consume_output(b'\x06\x24\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test'
                                  b'\x16\x03\x1b\x01\xc8\x17\x00', timeout=0.5)

    async def app_main(self):
        @self.app.route('/not')
        def on_interest(name, _app_param, reply: app.ReplyFunc, context):
            assert context['raw_packet'] == b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05'
            assert not context['sig_ptrs'].signature_info
            reply(self.app.make_data(name, b'test', signer=sec.NullSigner()))


class TestImplicitSha256(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x2d\x07\x28\x08\x04test\x01\x20'
                                  b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
                                  b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'
                                  b'\x0c\x01\x05'
                                  b'\x05\x2d\x07\x28\x08\x04test\x01\x20'
                                  b'\x54\x88\xf2\xc1\x1b\x56\x6d\x49\xe9\x90\x4f\xb5\x2a\xa6\xf6\xf9'
                                  b'\xe6\x6a\x95\x41\x68\x10\x9c\xe1\x56\xee\xa2\xc9\x2c\x57\xe4\xc2'
                                  b'\x0c\x01\x05')
        await face.input_packet(b'\x06\x13\x07\x06\x08\x04test\x14\x03\x18\x01\x00\x15\x04test')
        await aio.sleep(0.1)

    async def app_main(self):
        fut1 = self.app.express(
            '/test/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF',
            validator=app.pass_all, nonce=None, lifetime=5)
        fut2 = self.app.express(
            '/test/sha256digest=5488f2c11b566d49e9904fb52aa6f6f9e66a954168109ce156eea2c92c57e4c2',
            validator=app.pass_all, nonce=None, lifetime=5)
        name2, content2, _ = await fut2
        with pytest.raises(types.InterestTimeout):
            await fut1
        assert name2 == enc.Name.from_str('/test')
        assert content2 == b'test'


class TestPitToken(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x64\x1f\x62\x04\x01\x02\x03\x04\x50\x17'
                                b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.consume_output(b'\x64\x2e\x62\x04\x01\x02\x03\x04\x50\x26'
                                  b'\x06\x24\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test'
                                  b'\x16\x03\x1b\x01\xc8\x17\x00')

    async def app_main(self):
        @self.app.route('/not')
        def on_interest(name, _app_param, reply: app.ReplyFunc, _context):
            data = self.app.make_data(name, b'test', signer=sec.NullSigner())
            assert reply(data)
