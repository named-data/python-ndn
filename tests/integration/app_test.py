# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 Xinyu Ma
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
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestNack, InterestTimeout, ValidationFailure
from ndn.encoding import Component, Name, FormalName, SignaturePtrs
from ndn.transport.dummy_face import DummyFace
from ndn.security import KeychainDigest


class NDNAppTestSuite:
    app = None

    def test_main(self):
        face = DummyFace(self.face_proc)
        keychain = KeychainDigest()
        self.app = NDNApp(face, keychain)
        face.app = self.app
        self.app.run_forever(after_start=self.app_main())

    @abc.abstractmethod
    async def face_proc(self, face: DummyFace):
        pass

    @abc.abstractmethod
    async def app_main(self):
        pass


class TestConsumerBasic(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x050\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                  b'$\x08\x00\x00\x01m\xa4\xf3\xffm\x12\x00\x0c\x02\x17p')
        await face.input_packet(b'\x06B\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                b'$\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8'
                                b'\x15\rHello, world!')

    async def app_main(self):
        name = f'/example/testApp/randomData/{Component.TYPE_TIMESTAMP}=%00%00%01%6d%a4%f3%ff%6d'
        data_name, meta_info, content = await self.app.express_interest(
            name, must_be_fresh=True, can_be_prefix=False, lifetime=6000, nonce=None)
        assert data_name == Name.from_str(name)
        assert meta_info.freshness_period == 1000
        assert content == b'Hello, world!'


class TestInterestCancel(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x15\x07\x0f\x08\rnot important\x0c\x02\x0f\xa0')

    async def app_main(self):
        with pytest.raises(InterestCanceled):
            await self.app.express_interest('not important', nonce=None)


class TestInterestNack(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events'
                                  b'\x21\x00\x12\x00\x0c\x02\x03\xe8')
        await face.input_packet(b'\x64\x36\xfd\x03 \x05\xfd\x03!\x01\x96'
                                b'P\x43\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events'
                                b'\x21\x00\x12\x00\x0c\x02\x03\xe8')

    async def app_main(self):
        with pytest.raises(InterestNack) as nack:
            await self.app.express_interest('/localhost/nfd/faces/events', nonce=None, lifetime=1000,
                                            must_be_fresh=True, can_be_prefix=True)
        assert nack.value.reason == 150


class TestInterestTimeout(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x14\x07\x0f\x08\rnot important\x0c\x01\x01')
        await aio.sleep(0.002)

    async def app_main(self):
        with pytest.raises(InterestTimeout):
            await self.app.express_interest('not important', nonce=None, lifetime=1)


class TestDataValidationFalure(NDNAppTestSuite):
    @staticmethod
    async def validator(_name: FormalName, _sig: SignaturePtrs) -> bool:
        await aio.sleep(0.003)
        return False

    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x1b\x07\x10\x08\x03not\x08\timportant\n\x04\x00\x00\x00\x00\x0c\x01\x05')
        await face.input_packet(b'\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test')

    async def app_main(self):
        with pytest.raises(ValidationFailure) as e:
            await self.app.express_interest('/not/important', nonce=0, lifetime=5, validator=self.validator)
        assert e.value.name == Name.from_str('/not/important')
        assert e.value.content == b'test'


class TestInterestCanBePrefix(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x05\x0a\x07\x05\x08\x03not\x0c\x01\x05'
                                  b'\x05\x0c\x07\x05\x08\x03not\x21\x00\x0c\x01\x05'
                                  b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.input_packet(b'\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test')
        await aio.sleep(0.007)

    async def app_main(self):
        future1 = self.app.express_interest('/not', nonce=None, lifetime=5, can_be_prefix=False)
        future2 = self.app.express_interest('/not', nonce=None, lifetime=5, can_be_prefix=True)
        future3 = self.app.express_interest('/not/important', nonce=None, lifetime=5, can_be_prefix=False)
        name2, _, content2 = await future3
        name1, _, content1 = await future2
        with pytest.raises(InterestTimeout):
            await future1
        assert name1 == Name.from_str('/not/important')
        assert content1 == b'test'
        assert name2 == Name.from_str('/not/important')
        assert content2 == b'test'


class TestRoute(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.consume_output(b'\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test')

    async def app_main(self):
        @self.app.route('/not')
        def on_interest(name, _param, _app_param):
            self.app.put_data(name, b'test', no_signature=True)


class TestNoValidationNeededInterest(NDNAppTestSuite):
    counter = 0

    @staticmethod
    async def validator(_name: FormalName, _sig: SignaturePtrs) -> bool:
        return False

    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await aio.sleep(0.005)
        assert self.counter == 1

    async def app_main(self):
        @self.app.route('/not', validator=self.validator)
        def on_interest(_name, _param, _app_param):
            self.counter += 1


class TestInvalidInterest(NDNAppTestSuite):
    @staticmethod
    async def validator(_name: FormalName, _sig: SignaturePtrs) -> bool:
        return False

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
        def on_interest(_name, _param, _app_param):
            raise ValueError('This test fails')


class TestRoute2(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.ignore_output(0)
        await face.input_packet(b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05')
        await face.consume_output(b'\x06\x1d\x07\x10\x08\x03not\x08\timportant\x14\x03\x18\x01\x00\x15\x04test')

    async def app_main(self):
        @self.app.route('/not', need_raw_packet=True, need_sig_ptrs=True)
        def on_interest(name, _param, _app_param, raw_packet, sig_ptrs):
            assert raw_packet == b'\x05\x15\x07\x10\x08\x03not\x08\timportant\x0c\x01\x05'
            assert not sig_ptrs.signature_info
            self.app.put_data(name, b'test', no_signature=True)


class TestConsumerRawPacket(NDNAppTestSuite):
    async def face_proc(self, face: DummyFace):
        await face.consume_output(b'\x050\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                  b'$\x08\x00\x00\x01m\xa4\xf3\xffm\x12\x00\x0c\x02\x17p')
        await face.input_packet(b'\x06B\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                                b'$\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8'
                                b'\x15\rHello, world!')

    async def app_main(self):
        name = f'/example/testApp/randomData/{Component.TYPE_TIMESTAMP}=%00%00%01%6d%a4%f3%ff%6d'
        _, _, _, raw = await self.app.express_interest(
            name, must_be_fresh=True, can_be_prefix=False, lifetime=6000, nonce=None, need_raw_packet=True)
        assert (raw == b'\x06\x42\x07(\x08\x07example\x08\x07testApp\x08\nrandomData'
                       b'$\x08\x00\x00\x01m\xa4\xf3\xffm\x14\x07\x18\x01\x00\x19\x02\x03\xe8'
                       b'\x15\rHello, world!')
