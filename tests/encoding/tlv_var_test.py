import pytest
import struct
from ndn.encoding import write_tl_num, pack_uint_bytes, parse_tl_num, get_tl_num_size


class TestWriteTlNum:
    @staticmethod
    def test_1():
        buf = bytearray(10)
        siz = write_tl_num(0, buf, 1)
        assert buf == b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        assert siz == 1

    @staticmethod
    def test_2():
        buf = bytearray(10)
        siz = write_tl_num(255, buf, 1)
        assert buf == b'\x00\xfd\x00\xff\x00\x00\x00\x00\x00\x00'
        assert siz == 3

    @staticmethod
    def test_3():
        buf = bytearray(1)
        siz = write_tl_num(192, buf)
        assert buf == b'\xc0'
        assert siz == 1

    @staticmethod
    def test_4():
        buf = bytearray(5)
        siz = write_tl_num(65537, buf)
        assert buf == b'\xfe\x00\x01\x00\x01'
        assert siz == 5

    @staticmethod
    def test_5():
        buf = bytearray(9)
        siz = write_tl_num(5000000000, buf)
        assert buf == b'\xff\x00\x00\x00\x01*\x05\xf2\x00'
        assert siz == 9


class TestPackUintBytes:
    @staticmethod
    def test_1():
        assert pack_uint_bytes(1) == b'\x01'

    @staticmethod
    def test_2():
        assert pack_uint_bytes(255) == b'\xff'

    @staticmethod
    def test_3():
        assert pack_uint_bytes(256) == b'\x01\x00'

    @staticmethod
    def test_4():
        assert pack_uint_bytes(65537) == b'\x00\x01\x00\x01'

    @staticmethod
    def test_5():
        assert pack_uint_bytes(5000000000) == b'\x00\x00\x00\x01*\x05\xf2\x00'

    @staticmethod
    def test_6():
        with pytest.raises(struct.error):
            pack_uint_bytes(-1)


class TestParseTlNum:
    @staticmethod
    def test_1():
        assert parse_tl_num(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') == (0, 1)

    @staticmethod
    def test_2():
        assert parse_tl_num(b'\x00\xfd\x00\xff\x00\x00\x00\x00\x00\x00', 1) == (255, 3)

    @staticmethod
    def test_3():
        assert parse_tl_num(b'\xfe\xfe\x00\x01\x00\x01', 1) == (65537, 5)

    @staticmethod
    def test_4():
        assert parse_tl_num(b'\xff\x00\x00\x00\x01*\x05\xf2\x00') == (5000000000, 9)


class TestGetTlNumSize:
    @staticmethod
    def test_1():
        assert get_tl_num_size(0) == 1
        assert get_tl_num_size(253) == 3
        assert get_tl_num_size(65535) == 3
        assert get_tl_num_size(65536) == 5
        assert get_tl_num_size(10000000000) == 9
