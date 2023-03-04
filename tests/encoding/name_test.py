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
import pytest
from ndn.encoding import Name, Component


class TestComponent:
    @staticmethod
    def test_generic():
        comp = b'\x08\x0andn-python'
        assert Component.get_type(comp) == Component.TYPE_GENERIC
        assert Component.to_str(comp) == 'ndn-python'
        assert Component.from_str('ndn-python') == comp
        assert Component.from_str('8=ndn-python') == comp

        comp = b"\x08\x07foo%bar"
        assert Component.to_str(comp) == "foo%25bar"
        assert Component.from_str('foo%25bar') == comp
        assert Component.from_str('8=foo%25bar') == comp

        comp = b'\x08\x04-._~'
        assert Component.to_str(comp) == "-._~"
        assert Component.from_str('-._~') == comp
        assert Component.from_str('8=-._~') == comp

        with pytest.raises(ValueError):
            Component.from_str(":/?#[]@")
        comp = Component.from_bytes(b':/?#[]@')
        assert Component.to_str(comp) == "%3A%2F%3F%23%5B%5D%40"
        assert Component.from_str("%3a%2f%3f%23%5b%5d%40") == comp

        with pytest.raises(ValueError):
            Component.from_str("/")
        assert Component.from_str('') == b'\x08\x00'
        assert Component.from_bytes(b'') == b'\x08\x00'
        # '...' is not supported

    @staticmethod
    def sha256_tester(typ, uri_prefix):
        hex_text = '%28%ba%d4%b5%27%5b%d3%92%db%b6%70%c7%5c%f0%b6%6f%13%f7%94%2b%21%e8%0f%55%c0%e8%6b%37%47%53%a5%48'
        hex_lower = ''.join(hex_text.split('%'))
        hex_upper = hex_lower.upper()

        comp = Component.from_bytes(bytes.fromhex(hex_upper), typ=typ)
        assert Component.get_type(comp) == typ
        assert Component.to_str(comp) == uri_prefix + hex_lower
        assert Component.from_str(uri_prefix + hex_lower) == comp
        assert Component.from_str(uri_prefix + hex_upper) == comp
        # Component doesn't check the length of hash

    def test_implicit_sha256(self):
        self.sha256_tester(Component.TYPE_IMPLICIT_SHA256, 'sha256digest=')

    def test_params_sha256(self):
        self.sha256_tester(Component.TYPE_PARAMETERS_SHA256, 'params-sha256=')

    @staticmethod
    def test_other_types():
        comp = b'\x09\x039\x3dA'
        assert Component.to_str(comp) == "9=9%3DA"
        assert Component.from_str('9%3DA') != comp
        assert Component.from_str('9=9%3DA') == comp

        comp = bytes.fromhex('FDFFFF00')
        assert Component.get_type(comp) == 0xffff
        assert Component.to_str(comp) == '65535='

        comp = bytearray.fromhex('FD576501 2E')
        assert Component.get_type(comp) == 0x5765
        assert Component.to_str(comp) == '22373=.'

    @staticmethod
    def test_invalid_type():
        # 0-typed component is now checked in ndn-python
        with pytest.raises(ValueError):
            Component.from_str("0=A")
        with pytest.raises(ValueError):
            Component.from_str("-1=A")
        with pytest.raises(ValueError):
            Component.from_str("+=A")
        with pytest.raises(ValueError):
            Component.from_str("1=2=A")
        with pytest.raises(ValueError):
            Component.from_str("==A")
        with pytest.raises(ValueError):
            Component.from_str("%%")
        with pytest.raises(ValueError):
            Component.from_str("ABCD%EF%0")
        with pytest.raises(ValueError):
            Component.from_str("ABCD%GH")
        with pytest.raises(ValueError):
            Component.to_str(b'\x00\x01ABC')
        with pytest.raises(ValueError):
            Component.from_str('sha256digest=a04z')
        with pytest.raises(ValueError):
            Component.from_str('65536=a04z')

    @staticmethod
    def test_compare():
        comps = [
            Component.from_hex('0000000000000000000000000000000000000000000000000000000000000000', 1),
            Component.from_hex('0000000000000000000000000000000000000000000000000000000000000001', 1),
            Component.from_hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 1),
            Component.from_hex('0000000000000000000000000000000000000000000000000000000000000000', 2),
            Component.from_hex('0000000000000000000000000000000000000000000000000000000000000001', 2),
            Component.from_hex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF', 2),
            Component.from_bytes(b'', 0x03),
            Component.from_bytes(b'\x44', 0x03),
            Component.from_bytes(b'\x46', 0x03),
            Component.from_bytes(b'\x41\x41', 0x03),
            Component.from_str(''),
            Component.from_str('D'),
            Component.from_str('F'),
            Component.from_str('AA'),
            Component.from_str('21426='),
            Component.from_str('21426=%44'),
            Component.from_str('21426=%46'),
            Component.from_str('21426=%41%41')
        ]
        for i, lhs in enumerate(comps):
            for j, rhs in enumerate(comps):
                assert (lhs == rhs) == (i == j)
                assert (lhs != rhs) == (i != j)
                assert (lhs <  rhs) == (i <  j)
                assert (lhs <= rhs) == (i <= j)
                assert (lhs >  rhs) == (i >  j)
                assert (lhs >= rhs) == (i >= j)

    @staticmethod
    def test_number():
        assert Component.from_segment(13) == b'\x32\x01\r'
        assert Component.from_byte_offset(13) == b'\x34\x01\r'
        assert Component.from_sequence_num(13) == b'\x3a\x01\r'
        assert Component.from_version(13) == b'\x36\x01\r'
        timeval = 15686790223318112
        comp = Component.from_timestamp(timeval)
        assert Component.get_type(comp) == 0x38
        assert Component.get_value(comp) == b'\x00\x37\xbb\x0d\x76\xed\x4c\x60'
        assert Component.to_number(comp) == timeval

        assert Component.to_str(Component.from_segment(13)) == 'seg=13'
        assert Component.to_str(Component.from_byte_offset(13)) == 'off=13'
        assert Component.to_str(Component.from_sequence_num(13)) == 'seq=13'
        assert Component.to_str(Component.from_version(13)) == 'v=13'
        assert Component.to_str(Component.from_timestamp(timeval)) == 't=15686790223318112'

        assert Component.from_str('seg=13') == b'\x32\x01\r'
        assert Component.from_str('off=13') == b'\x34\x01\r'
        assert Component.from_str('seq=13') == b'\x3a\x01\r'
        assert Component.from_str('v=13') == b'\x36\x01\r'
        assert Component.from_str('t=15686790223318112') == b'\x38\x08\x007\xbb\rv\xedL`'


class TestName:
    @staticmethod
    def test_basic_encode():
        uri = ('/Emid/25042=P3//./%1C%9F'
               '/sha256digest=0415e3624a151850ac686c84f155f29808c0dd73819aa4a4c20be73a4d8a874c')
        name = Name.from_str(uri)
        assert len(name) == 6
        assert name[0] == Component.from_bytes(b'Emid')
        assert name[1] == b'\xfd\x61\xd2\x02\x50\x33'
        assert name[2] == Component.from_bytes(b'')
        assert name[3] == Component.from_bytes(b'.')
        assert name[4] == Component.from_bytes(b'\x1C\x9F')
        assert Component.get_type(name[5]) == Component.TYPE_IMPLICIT_SHA256

        assert Name.encoded_length(name) == 57
        assert (Name.encode(name) ==
                b'\x07\x37\x08\x04Emid\xfda\xd2\x02P3\x08\x00\x08\x01.\x08\x02\x1c\x9f'
                b'\x01 \x04\x15\xe3bJ\x15\x18P\xachl\x84\xf1U\xf2\x98\x08\xc0\xdds\x81'
                b'\x9a\xa4\xa4\xc2\x0b\xe7:M\x8a\x87L')

    @staticmethod
    def test_string_parse():
        assert Name.to_str(Name.from_str('/hello/world')) == '/hello/world'
        assert Name.to_str(Name.from_str('hello/world')) == '/hello/world'
        assert Name.to_str(Name.from_str('hello/world/')) == '/hello/world'

        assert Name.to_str(Name.from_str('hello/world/  ')) == '/hello/world/%20%20'
        assert Name.to_str(Name.from_str('/:?#[]@')) == '/%3A%3F%23%5B%5D%40'
        assert Name.to_str(Name.from_str(' hello\t/\tworld \r\n')) == '/%20hello%09/%09world%20%0D%0A'

        assert Name.to_str(Name.from_str('')) == '/'
        assert Name.to_str(Name.from_str(' ')) == '/%20'
        assert Name.to_str(Name.from_str('/hello//world')) == '/hello//world'
        assert Name.to_str(Name.from_str('/hello/./world')) == '/hello/./world'
        assert Name.to_str(Name.from_str('/hello/../world')) == '/hello/../world'
        assert Name.to_str(Name.from_str('//')) == '//'

    @staticmethod
    def test_compare():
        strs = [
            "/",
            "/sha256digest=0000000000000000000000000000000000000000000000000000000000000000",
            "/sha256digest=0000000000000000000000000000000000000000000000000000000000000001",
            "/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "/params-sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "/params-sha256=0000000000000000000000000000000000000000000000000000000000000001",
            "/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "/3=",
            "/3=D",
            "/3=F",
            "/3=AA",
            "//",
            "/D",
            "/D/sha256digest=0000000000000000000000000000000000000000000000000000000000000000",
            "/D/sha256digest=0000000000000000000000000000000000000000000000000000000000000001",
            "/D/sha256digest=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "/D/params-sha256=0000000000000000000000000000000000000000000000000000000000000000",
            "/D/params-sha256=0000000000000000000000000000000000000000000000000000000000000001",
            "/D/params-sha256=FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            "/D/3=",
            "/D/3=D",
            "/D/3=F",
            "/D/3=AA",
            "/D//",
            "/D/D",
            "/D/F",
            "/D/AA",
            "/D/21426=/",
            "/D/21426=D",
            "/D/21426=F",
            "/D/21426=AA",
            "/F",
            "/AA",
            "/21426=",
            "/21426=D",
            "/21426=F",
            "/21426=AA",
        ]
        names = [Name.from_str(s) for s in strs]
        for i, lhs in enumerate(names):
            for j, rhs in enumerate(names):
                assert (lhs == rhs) == (i == j)
                assert (lhs != rhs) == (i != j)
                assert (lhs <  rhs) == (i <  j)
                assert (lhs <= rhs) == (i <= j)
                assert (lhs >  rhs) == (i >  j)
                assert (lhs >= rhs) == (i >= j)

    @staticmethod
    def test_is_prefix():
        assert Name.is_prefix(Name.from_str('/'), Name.from_str('/'))
        assert Name.is_prefix(Name.from_str('/'), Name.from_str('/3=D'))
        assert Name.is_prefix(Name.from_str('/'), Name.from_str('/F'))
        assert Name.is_prefix(Name.from_str('/'), Name.from_str('/21426=AA'))

        assert Name.is_prefix(Name.from_str('/B'), Name.from_str('/B'))
        assert Name.is_prefix(Name.from_str('/B'), Name.from_str('/B/3=D'))
        assert Name.is_prefix(Name.from_str('/B'), Name.from_str('/B/F'))
        assert Name.is_prefix(Name.from_str('/B'), Name.from_str('/B/21426=AA'))

        assert not Name.is_prefix(Name.from_str('/C'), Name.from_str('/'))
        assert not Name.is_prefix(Name.from_str('/C'), Name.from_str('/3=D'))
        assert not Name.is_prefix(Name.from_str('/C'), Name.from_str('/F'))
        assert not Name.is_prefix(Name.from_str('/C'), Name.from_str('/21426=AA'))

    @staticmethod
    def test_encode_func():
        name = Name.from_str('/a/b/c/d')
        buf = bytearray(20)

        with pytest.raises(IndexError):
            Name.encode(name, buf, 10)
        assert Name.encode(name, buf, 6) == b'\x00\x00\x00\x00\x00\x00\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d'
        assert Name.encode(name, buf) == b'\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d\x08\x01c\x08\x01d'
        assert Name.encode([]) == b'\x07\x00'

    @staticmethod
    def test_decode_func():
        buf = b'\x00\x00\x00\x00\x00\x00\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01d'

        with pytest.raises(ValueError):
            Name.decode(buf, 10)
        with pytest.raises(IndexError):
            Name.decode(buf[:-1], 6)

        name, size_name = Name.decode(buf, 6)
        assert size_name == 14
        assert len(name) == 4
        assert name[0] == b'\x08\x01a'
        assert name[1] == b'\x08\x01b'
        assert name[2] == b'\x08\x01c'
        assert name[3] == b'\x08\x01d'

        assert Name.decode(b'\x07\x00') == ([], 2)

    @staticmethod
    def test_normalize():
        name = b'\x07\x0c\x08\x01a\x08\x01b\x08\x01c\x08\x01\x1d'
        assert Name.normalize(name) == [b'\x08\x01a', b'\x08\x01b', b'\x08\x01c', b'\x08\x01\x1d']

        name = '/8=a/b/%63/\x1d'
        assert Name.normalize(name) == [b'\x08\x01a', b'\x08\x01b', b'\x08\x01c', b'\x08\x01\x1d']

        name = ['8=a', 'b', b'\x08\x01c', '\x1d']
        assert Name.normalize(name) == [b'\x08\x01a', b'\x08\x01b', b'\x08\x01c', b'\x08\x01\x1d']

    @staticmethod
    def test_canonical_uri():
        assert Name.to_canonical_uri(Name.from_str('/hello/world')) == '/hello/world'
        assert Name.to_canonical_uri(Name.from_str('/8=hello/seg=1')) == '/hello/50=%01'
