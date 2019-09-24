import pytest
from typing import Union, List
from ndn.encoding.tlv_var import BinaryStr
from ndn.encoding.ndn_format_0_3 import *
from ndn.encoding.name import Name, Component


class TestInterestMake:
    @staticmethod
    def test_default():
        name = Name.from_str('/local/ndn/prefix')
        interest = make_interest(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

        name = Name.encode(name)
        interest = make_interest(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

        name = '/local/ndn/prefix'
        interest = make_interest(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

    @staticmethod
    def test_interest_params():
        name = '/local/ndn/prefix'
        int_param = InterestParam()
        int_param.can_be_prefix = True
        int_param.must_be_fresh = True
        int_param.hop_limit = 1
        int_param.nonce = 0
        int_param.lifetime = 10
        interest = make_interest(name, int_param)
        assert (interest == b'\x05\x26\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
                            b'\x21\x00\x12\x00\x0a\x04\x00\x00\x00\x00\x0c\x01\x0a\x22\x01\x01')

    @staticmethod
    def test_mixed_name():
        name = ['local', Component.from_str('ndn'), 'prefix']
        interest = make_interest(name, InterestParam())
        assert interest == b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'

    @staticmethod
    def test_app_param():
        name = '/local/ndn/prefix'
        app_param = b'\x01\x02\x03\x04'
        interest = make_interest(name, InterestParam(), app_param)
        assert (interest ==
                b'\x05\x42\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 Guo!\xfe\x0e\xe2e\x14\x9a\xa2\xbe<c\xc58\xa7#x\xe9\xb0\xa5\x8b9\xc5\x91cg\xd3[\xda\x10'
                b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')

        name = '/test/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF/ndn'
        interest = make_interest(name, InterestParam(), app_param)
        assert (interest ==
                b'\x05\x39\x07\x2d\x08\x04test'
                b'\x02 Guo!\xfe\x0e\xe2e\x14\x9a\xa2\xbe<c\xc58\xa7#x\xe9\xb0\xa5\x8b9\xc5\x91cg\xd3[\xda\x10'
                b'\x08\x03ndn'
                b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')

    @staticmethod
    def test_signed_interest():
        name = '/local/ndn/prefix'
        app_param = b'\x01\x02\x03\x04'
        int_param = InterestParam()
        int_param.signature_type = 0
        int_param.nonce = 0x6c211166
        interest = make_interest(name, int_param, app_param)
        assert (interest ==
                b'\x05o\x076\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 \x8en6\xd7\xea\xbc\xdeCua@\xc9\x0b\xda\t\xd5'
                b'\x00\xd2\xa5w\xf2\xf53\xb5i\xf0D\x1d\xf0\xa7\xf9\xe2'
                b'\n\x04l!\x11f\x0c\x02\x0f\xa0'
                b'$\x04\x01\x02\x03\x04'
                b',\x03\x1b\x01\x00'
                b'. \xea\xa8\xf0\x99\x08cx\x95\x1d\xe0_\xf1\xde\xbb\xc1\x18'
                b'\xb5!\x8b/\xca\xa0\xb5\x1d\x18\xfa\xbc)\xf5MX\xff')

        interest = make_interest(name, int_param)
        assert (interest ==
                b'\x05k\x076\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 @w\xa5pI\xd88H\xb5%\xa4#\xab\x97\x8ed'
                b'\x80\xf9m\\\xa3\x8a\x80\xa5\xe2\xd6\xe2P\xa6\x17\xbeO'
                b'\n\x04l!\x11f\x0c\x02\x0f\xa0'
                b'$\x00'
                b',\x03\x1b\x01\x00'
                b'. \tN\x00\x9dtY\x82\\\xa0-\xaa\xb7\xad`H0'
                b'9\x19\xd8\x99\x80%\xbe\xff\xa6\xf9\x96y\xd6^\x9fb')


class TestDataMake:
    @staticmethod
    def test_default():
        name = Name.from_str('/local/ndn/prefix')
        data = make_data(name, DataParam())
        assert (data ==
                b"\x06B\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x7f1\xe4\t\xc5z/\x1d\r\xdaVh8\xfd\xd9\x94\xd8\'S\x13[\xd7\x15\xa5\x9d%^\x80\xf2\xab\xf0\xb5")

        name = Name.encode(name)
        data = make_data(name, DataParam())
        assert (data ==
                b"\x06B\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x7f1\xe4\t\xc5z/\x1d\r\xdaVh8\xfd\xd9\x94\xd8\'S\x13[\xd7\x15\xa5\x9d%^\x80\xf2\xab\xf0\xb5")

        name = '/local/ndn/prefix'
        data = make_data(name, DataParam())
        assert (data ==
                b"\x06B\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x7f1\xe4\t\xc5z/\x1d\r\xdaVh8\xfd\xd9\x94\xd8\'S\x13[\xd7\x15\xa5\x9d%^\x80\xf2\xab\xf0\xb5")
