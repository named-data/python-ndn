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
import hashlib
import pytest
from typing import List
from ndn.security import DigestSha256Signer
from ndn.encoding import Name, Component, InterestParam, MetaInfo, ContentType, SignatureType, \
    make_interest, make_data, parse_interest, parse_data, DecodeError, Signer, VarBinaryStr


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
        interest, final_name = make_interest(name, InterestParam(), app_param, need_final_name=True)
        assert (interest ==
                b'\x05\x42\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 \x47\x75\x6f\x21\xfe\x0e\xe2\x65\x14\x9a\xa2\xbe\x3c\x63\xc5\x38'
                b'\xa7\x23\x78\xe9\xb0\xa5\x8b\x39\xc5\x91\x63\x67\xd3\x5b\xda\x10'
                b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')
        assert (final_name
                == Name.decode(b'\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                               b'\x02 \x47\x75\x6f\x21\xfe\x0e\xe2\x65\x14\x9a\xa2\xbe\x3c\x63\xc5\x38'
                               b'\xa7\x23\x78\xe9\xb0\xa5\x8b\x39\xc5\x91\x63\x67\xd3\x5b\xda\x10')[0])

        name = '/test/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF/ndn'
        interest = make_interest(name, InterestParam(), app_param)
        assert (interest ==
                b'\x05\x39\x07\x2d\x08\x04test'
                b'\x02 \x47\x75\x6f\x21\xfe\x0e\xe2\x65\x14\x9a\xa2\xbe\x3c\x63\xc5\x38'
                b'\xa7\x23\x78\xe9\xb0\xa5\x8b\x39\xc5\x91\x63\x67\xd3\x5b\xda\x10'
                b'\x08\x03ndn'
                b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')

    @staticmethod
    def test_signed_interest():
        name = '/local/ndn/prefix'
        app_param = b'\x01\x02\x03\x04'
        int_param = InterestParam()
        int_param.nonce = 0x6c211166
        interest = make_interest(name, int_param, app_param, signer=DigestSha256Signer())
        assert (interest ==
                b'\x05\x6f\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 \x8e\x6e\x36\xd7\xea\xbc\xde\x43\x75\x61\x40\xc9\x0b\xda\x09\xd5'
                b'\x00\xd2\xa5\x77\xf2\xf5\x33\xb5\x69\xf0\x44\x1d\xf0\xa7\xf9\xe2'
                b'\x0a\x04\x6c\x21\x11\x66\x0c\x02\x0f\xa0'
                b'\x24\x04\x01\x02\x03\x04'
                b'\x2c\x03\x1b\x01\x00'
                b'\x2e \xea\xa8\xf0\x99\x08\x63\x78\x95\x1d\xe0\x5f\xf1\xde\xbb\xc1\x18'
                b'\xb5\x21\x8b\x2f\xca\xa0\xb5\x1d\x18\xfa\xbc\x29\xf5\x4d\x58\xff')

        interest = make_interest(name, int_param, signer=DigestSha256Signer())
        assert (interest ==
                b'\x05\x6b\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x02 \x40\x77\xa5\x70\x49\xd8\x38\x48\xb5\x25\xa4\x23\xab\x97\x8e\x64'
                b'\x80\xf9\x6d\x5c\xa3\x8a\x80\xa5\xe2\xd6\xe2\x50\xa6\x17\xbe\x4f'
                b'\x0a\x04\x6c\x21\x11\x66\x0c\x02\x0f\xa0'
                b'\x24\x00'
                b'\x2c\x03\x1b\x01\x00'
                b'\x2e \x09\x4e\x00\x9d\x74\x59\x82\x5c\xa0\x2d\xaa\xb7\xad\x60\x48\x30'
                b'\x39\x19\xd8\x99\x80\x25\xbe\xff\xa6\xf9\x96\x79\xd6\x5e\x9f\x62')

    @staticmethod
    def test_forwarding_hint():
        name = '/local/ndn/prefix'
        int_param = InterestParam()
        int_param.nonce = 0x01020304
        int_param.forwarding_hint = [
            '/name/A',
            Name.from_str('/ndn/B'),
            b'\x07\x0d\x08\x0bshekkuenseu'
        ]
        interest = make_interest(name, int_param)
        assert (interest ==
                b'\x05\x46\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x1e\x24'
                b'\x07\x09\x08\x04name\x08\x01A'
                b'\x07\x08\x08\x03ndn\x08\x01B'
                b'\x07\r\x08\x0bshekkuenseu'
                b'\x0a\x04\x01\x02\x03\x04\x0c\x02\x0f\xa0')

    @staticmethod
    def test_throws():
        with pytest.raises(ValueError):
            make_interest("/invalid%%name", InterestParam())

        with pytest.raises(TypeError):
            make_interest("/ndn", InterestParam(lifetime=0.5))

        with pytest.raises(TypeError):
            make_interest("/ndn", InterestParam(forwarding_hint=[1, 2, 3]))

        with pytest.raises(ValueError):
            make_interest("/ndn", InterestParam(hop_limit=300))

        with pytest.raises(ValueError):
            make_interest("/params-sha256=4077", InterestParam())

        with pytest.raises(ValueError):
            make_interest("/params-sha256=4077", InterestParam(), b'')


class TestDataMake:
    @staticmethod
    def test_default():
        name = Name.from_str('/local/ndn/prefix')
        data = make_data(name, MetaInfo(), signer=DigestSha256Signer())
        assert (data ==
                b"\x06\x42\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x7f1\xe4\t\xc5z/\x1d\r\xdaVh8\xfd\xd9\x94"
                b"\xd8\'S\x13[\xd7\x15\xa5\x9d%^\x80\xf2\xab\xf0\xb5")

        name = Name.encode(name)
        data = make_data(name, MetaInfo(), b'01020304', signer=DigestSha256Signer())
        assert (data ==
                b'\x06L\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x14\x03\x18\x01\x00'
                b'\x15\x0801020304'
                b'\x16\x03\x1b\x01\x00'
                b'\x17 \x94\xe9\xda\x91\x1a\x11\xfft\x02i:G\x0cO\xdd!'
                b'\xe0\xc7\xb6\xfd\x8f\x9cn\xc5\x93{\x93\x04\xe0\xdf\xa6S')

        name = '/local/ndn/prefix'
        meta_info = MetaInfo()
        data = make_data(name, meta_info)
        assert (data ==
                b"\x06\x1b\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00")

        name = '/E'
        meta_info = MetaInfo()
        meta_info.content_type = None
        data = make_data(name, meta_info, b'', signer=DigestSha256Signer())
        assert data == bytes.fromhex("0630 0703080145"
                                     "1400 1500 16031b0100"
                                     "1720f965ee682c6973c3cbaa7b69e4c7063680f83be93a46be2ccc98686134354b66")

    @staticmethod
    def test_meta_info():
        name = '/local/ndn/prefix/37=%00'
        meta_info = MetaInfo()
        meta_info.content_type = ContentType.BLOB
        meta_info.freshness_period = 1000
        meta_info.final_block_id = Component.from_sequence_num(2)
        data = make_data(name, meta_info, signer=DigestSha256Signer())
        assert (data ==
                b"\x06\x4e\x07\x17\x08\x05local\x08\x03ndn\x08\x06prefix\x25\x01\x00"
                b"\x14\x0c\x18\x01\x00\x19\x02\x03\xe8\x1a\x03\x3a\x01\x02"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x0f^\xa1\x0c\xa7\xf5Fb\xf0\x9cOT\xe0FeC\x8f92\x04\x9d\xabP\x80o\'\x94\xaa={hQ")

    @staticmethod
    def test_shrink_signature():
        class ShrinkSigner(Signer):
            def write_signature_info(self, signature_info):
                pass

            def get_signature_value_size(self) -> int:
                return 10

            def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
                return 5

        name = '/test'
        meta_info = MetaInfo(content_type=ContentType.BLOB)
        data = make_data(name, meta_info, signer=ShrinkSigner())
        assert data == b'\x06\x16\x07\x06\x08\x04test\x14\x03\x18\x01\x00\x16\x00\x17\x05\x00\x00\x00\x00\x00'


class TestInterestParse:
    @staticmethod
    def test_default():
        interest = b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix\x0c\x02\x0f\xa0'
        name, params, app_params, sig = parse_interest(interest)
        assert name == Name.from_str('/local/ndn/prefix')
        assert app_params is None
        assert not params.can_be_prefix
        assert not params.must_be_fresh
        assert params.nonce is None
        assert params.lifetime == 4000
        assert params.hop_limit is None
        assert sig.signature_info is None
        assert sig.signature_value_buf is None
        assert sig.digest_value_buf is None

    @staticmethod
    def test_params():
        interest = (b'\x05\x26\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
                    b'\x21\x00\x12\x00\x0a\x04\x00\x00\x00\x00\x0c\x01\x0a\x22\x01\x01')
        name, params, app_params, sig = parse_interest(interest)
        assert name == Name.from_str('/local/ndn/prefix')
        assert app_params is None
        assert params.can_be_prefix
        assert params.must_be_fresh
        assert params.nonce == 0
        assert params.lifetime == 10
        assert params.hop_limit == 1
        assert sig.signature_info is None
        assert sig.signature_value_buf is None
        assert sig.digest_value_buf is None

    @staticmethod
    def test_app_param():
        interest = (b'\x05\x42\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                    b'\x02 \x47\x75\x6f\x21\xfe\x0e\xe2\x65\x14\x9a\xa2\xbe\x3c\x63\xc5\x38'
                    b'\xa7\x23\x78\xe9\xb0\xa5\x8b\x39\xc5\x91\x63\x67\xd3\x5b\xda\x10'
                    b'\x0c\x02\x0f\xa0\x24\x04\x01\x02\x03\x04')
        name, params, app_params, sig = parse_interest(interest)
        assert name == Name.from_str('/local/ndn/prefix'
                                     '/params-sha256=47756f21fe0ee265149aa2be3c63c538a72378e9b0a58b39c5916367d35bda10')
        assert app_params == b'\x01\x02\x03\x04'
        assert not params.can_be_prefix
        assert not params.must_be_fresh
        assert params.nonce is None
        assert params.lifetime == 4000
        assert params.hop_limit is None
        assert sig.signature_info is None

        algo = hashlib.sha256()
        algo.update(b'\x24\x04\x01\x02\x03\x04')
        assert Component.get_value(name[-1]) == algo.digest()
        algo = hashlib.sha256()
        for part in sig.digest_covered_part:
            algo.update(part)
        assert sig.digest_value_buf == algo.digest()

    @staticmethod
    def test_signed_interest_1():
        interest = (b'\x05\x6f\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                    b'\x02 \x8e\x6e\x36\xd7\xea\xbc\xde\x43\x75\x61\x40\xc9\x0b\xda\x09\xd5'
                    b'\x00\xd2\xa5\x77\xf2\xf5\x33\xb5\x69\xf0\x44\x1d\xf0\xa7\xf9\xe2'
                    b'\x0a\x04\x6c\x21\x11\x66\x0c\x02\x0f\xa0'
                    b'\x24\x04\x01\x02\x03\x04'
                    b'\x2c\x03\x1b\x01\x00'
                    b'\x2e \xea\xa8\xf0\x99\x08\x63\x78\x95\x1d\xe0\x5f\xf1\xde\xbb\xc1\x18'
                    b'\xb5\x21\x8b\x2f\xca\xa0\xb5\x1d\x18\xfa\xbc\x29\xf5\x4d\x58\xff')
        name, params, app_params, sig = parse_interest(interest)
        assert name == Name.from_str("/local/ndn/prefix"
                                     "/params-sha256=8e6e36d7eabcde43756140c90bda09d500d2a577f2f533b569f0441df0a7f9e2")
        assert params.nonce == 0x6c211166
        assert app_params == b'\x01\x02\x03\x04'
        assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256

        algo = hashlib.sha256()
        for part in sig.digest_covered_part:
            algo.update(part)
        assert sig.digest_value_buf == algo.digest()

        algo = hashlib.sha256()
        for part in sig.signature_covered_part:
            algo.update(part)
        assert sig.signature_value_buf == algo.digest()

    @staticmethod
    def test_signed_interest_2():
        interest = (b'\x05\x6b\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
                    b'\x02 \x40\x77\xa5\x70\x49\xd8\x38\x48\xb5\x25\xa4\x23\xab\x97\x8e\x64'
                    b'\x80\xf9\x6d\x5c\xa3\x8a\x80\xa5\xe2\xd6\xe2\x50\xa6\x17\xbe\x4f'
                    b'\x0a\x04\x6c\x21\x11\x66\x0c\x02\x0f\xa0'
                    b'\x24\x00'
                    b'\x2c\x03\x1b\x01\x00'
                    b'\x2e \x09\x4e\x00\x9d\x74\x59\x82\x5c\xa0\x2d\xaa\xb7\xad\x60\x48\x30'
                    b'\x39\x19\xd8\x99\x80\x25\xbe\xff\xa6\xf9\x96\x79\xd6\x5e\x9f\x62')
        name, params, app_params, sig = parse_interest(interest)
        assert name == Name.from_str("/local/ndn/prefix"
                                     "/params-sha256=4077a57049d83848b525a423ab978e6480f96d5ca38a80a5e2d6e250a617be4f")
        assert params.nonce == 0x6c211166
        assert app_params == b''
        assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256

        algo = hashlib.sha256()
        for part in sig.digest_covered_part:
            algo.update(part)
        assert sig.digest_value_buf == algo.digest()

        algo = hashlib.sha256()
        for part in sig.signature_covered_part:
            algo.update(part)
        assert sig.signature_value_buf == algo.digest()

    @staticmethod
    def test_throws():
        with pytest.raises(IndexError):
            parse_interest(b'\x05\x6b\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix', True)

        with pytest.raises(IndexError):
            parse_interest(b'\x05\x6b\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix', True)

        with pytest.raises(ValueError):
            parse_interest(b'\x06\x6b\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix', True)

        with pytest.raises(DecodeError):
            parse_interest(b'\x01\x00', False)


class TestDataParse:
    @staticmethod
    def test_default_1():
        data = (b"\x06\x42\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x7f1\xe4\t\xc5z/\x1d\r\xdaVh8\xfd\xd9\x94"
                b"\xd8\'S\x13[\xd7\x15\xa5\x9d%^\x80\xf2\xab\xf0\xb5")
        name, meta_info, content, sig = parse_data(data)
        assert name == Name.from_str("/local/ndn/prefix")
        assert meta_info.content_type == ContentType.BLOB
        assert meta_info.freshness_period is None
        assert meta_info.final_block_id is None
        assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256
        assert content is None

        algo = hashlib.sha256()
        for part in sig.signature_covered_part:
            algo.update(part)
        assert sig.signature_value_buf == algo.digest()

    @staticmethod
    def test_default_2():
        data = (b'\x06L\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
                b'\x14\x03\x18\x01\x00'
                b'\x15\x0801020304'
                b'\x16\x03\x1b\x01\x00'
                b'\x17 \x94\xe9\xda\x91\x1a\x11\xfft\x02i:G\x0cO\xdd!'
                b'\xe0\xc7\xb6\xfd\x8f\x9cn\xc5\x93{\x93\x04\xe0\xdf\xa6S')
        name, meta_info, content, sig = parse_data(data)
        assert name == Name.from_str("/local/ndn/prefix")
        assert meta_info.content_type == ContentType.BLOB
        assert meta_info.freshness_period is None
        assert meta_info.final_block_id is None
        assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256
        assert content == b'01020304'

        algo = hashlib.sha256()
        for part in sig.signature_covered_part:
            algo.update(part)
        assert sig.signature_value_buf == algo.digest()

    @staticmethod
    def test_default_3():
        data = (b"\x06\x1b\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
                b"\x14\x03\x18\x01\x00")
        name, meta_info, content, sig = parse_data(data)
        assert name == Name.from_str("/local/ndn/prefix")
        assert meta_info.content_type == ContentType.BLOB
        assert meta_info.freshness_period is None
        assert meta_info.final_block_id is None
        assert sig.signature_info is None
        assert content is None
        assert sig.signature_value_buf is None

    @staticmethod
    def test_default_4():
        data = bytes.fromhex("0630 0703080145"
                             "1400 1500 16031b0100"
                             "1720f965ee682c6973c3cbaa7b69e4c7063680f83be93a46be2ccc98686134354b66")
        name, meta_info, content, sig = parse_data(data)
        assert name == Name.from_str("/E")
        assert meta_info.content_type is None
        assert meta_info.freshness_period is None
        assert meta_info.final_block_id is None
        assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256
        assert content == b''

        algo = hashlib.sha256()
        for part in sig.signature_covered_part:
            algo.update(part)
        assert sig.signature_value_buf == algo.digest()

    @staticmethod
    def test_meta_info():
        data = (b"\x06\x4e\x07\x17\x08\x05local\x08\x03ndn\x08\x06prefix\x25\x01\x00"
                b"\x14\x0c\x18\x01\x00\x19\x02\x03\xe8\x1a\x03\x3a\x01\x02"
                b"\x16\x03\x1b\x01\x00"
                b"\x17 \x0f^\xa1\x0c\xa7\xf5Fb\xf0\x9cOT\xe0FeC\x8f92\x04\x9d\xabP\x80o\'\x94\xaa={hQ")
        name, meta_info, content, sig = parse_data(data)
        assert name == Name.from_str("/local/ndn/prefix/37=%00")
        assert meta_info.content_type == ContentType.BLOB
        assert meta_info.freshness_period == 1000
        assert meta_info.final_block_id == Component.from_sequence_num(2)
        assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256
        assert content is None

        algo = hashlib.sha256()
        for part in sig.signature_covered_part:
            algo.update(part)
        assert sig.signature_value_buf == algo.digest()

    @staticmethod
    def test_none_meta_info():
        wire = b'\x06\x0f\x07\x06\x08\x01\x41\x08\x01\x31\x16\x03\x1b\x01\xc8\x17\x00'
        _, meta_info, _, _ = parse_data(wire)
        assert meta_info is not None
        assert meta_info.content_type == ContentType.BLOB
