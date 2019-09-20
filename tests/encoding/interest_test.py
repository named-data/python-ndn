import pytest
from ndn.encoding.interest import *


class TestInterest:
    @staticmethod
    def test_make__default():
        name = Name.from_str('/local/ndn/prefix')
        interest = Interest.make(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

        name = Name.encode(name)
        interest = Interest.make(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

        name = '/local/ndn/prefix'
        interest = Interest.make(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

    @staticmethod
    def test_make__interest_params():
        name = '/local/ndn/prefix'
        int_param = InterestParam()
        int_param.can_be_prefix = True
        int_param.must_be_fresh = True
        int_param.hop_limit = 1
        int_param.nonce = 0
        int_param.lifetime = 10
        interest = Interest.make(name, int_param)
        assert (interest == b'\x05\x26\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
                            b'\x21\x00\x12\x00\x0a\x04\x00\x00\x00\x00\x0c\x01\x0a\x22\x01\x01')

    @staticmethod
    def test_make__mixed_name():
        name = ['local', Component.from_str('ndn'), 'prefix']
        interest = Interest.make(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

    @staticmethod
    def test_make__app_param():
        name = '/local/ndn/prefix'
        app_param = b'\x01\x02\x03\x04'
        interest = Interest.make(name, InterestParam(), app_param)
        assert (interest ==
                b'\x05\x42\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 Guo!\xfe\x0e\xe2e\x14\x9a\xa2\xbe<c\xc58\xa7#x\xe9\xb0\xa5\x8b9\xc5\x91cg\xd3[\xda\x10'
                b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')

        name = '/test/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF/ndn'
        interest = Interest.make(name, InterestParam(), app_param)
        assert (interest ==
                b'\x05\x39\x07\x2d\x08\x04test'
                b'\x02 Guo!\xfe\x0e\xe2e\x14\x9a\xa2\xbe<c\xc58\xa7#x\xe9\xb0\xa5\x8b9\xc5\x91cg\xd3[\xda\x10'
                b'\x08\x03ndn'
                b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')
