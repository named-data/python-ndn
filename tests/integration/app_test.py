import abc
import asyncio as aio
import pytest
from ndn.app import NDNApp
from ndn.types import InterestCanceled, InterestNack, InterestTimeout
from ndn.encoding import Component, Name
from ndn.transport.dummy_face import DummyFace


class NDNAppTestSuite:
    app = None

    def test_main(self):
        self.app = NDNApp()
        self.app.face = DummyFace(self.face_proc, self.app)
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
