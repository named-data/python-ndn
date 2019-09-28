import struct
import asyncio as aio
from .tlv_type import BinaryStr, VarBinaryStr


def get_tl_num_size(val: int) -> int:
    if val <= 0xFC:
        return 1
    elif val <= 0xFFFF:
        return 3
    elif val <= 0xFFFFFFFF:
        return 5
    else:
        return 9


def write_tl_num(val: int, buf: VarBinaryStr, offset: int = 0) -> int:
    if val <= 0xFC:
        struct.pack_into('!B', buf, offset, val)
        return 1
    elif val <= 0xFFFF:
        struct.pack_into('!BH', buf, offset, 0xFD, val)
        return 3
    elif val <= 0xFFFFFFFF:
        struct.pack_into('!BI', buf, offset, 0xFE, val)
        return 5
    else:
        struct.pack_into('!BQ', buf, offset, 0xFF, val)
        return 9


def pack_uint_bytes(val: int) -> bytes:
    if val <= 0xFF:
        return struct.pack('!B', val)
    elif val <= 0xFFFF:
        return struct.pack('!H', val)
    elif val <= 0xFFFFFFFF:
        return struct.pack('!I', val)
    else:
        return struct.pack('!Q', val)


def parse_tl_num(buf: BinaryStr, offset: int = 0) -> (int, int):
    ret = buf[offset]
    if ret <= 0xFC:
        return ret, 1
    elif ret == 0xFD:
        return struct.unpack('!H', buf[offset+1:offset+3])[0], 3
    elif ret == 0xFE:
        return struct.unpack('!I', buf[offset+1:offset+5])[0], 5
    else:
        return struct.unpack('!Q', buf[offset+1:offset+9])[0], 9


def is_binary_str(var):
    return isinstance(var, bytes) or isinstance(var, bytearray) or isinstance(var, memoryview)


async def read_tl_num_from_stream(reader: aio.StreamReader) -> int:
    buf = await reader.readexactly(1)
    num = buf[0]
    if num <= 0xFC:
        return num
    elif num == 0xFD:
        buf = await reader.readexactly(2)
        return struct.unpack('!H', buf)[0]
    elif num == 0xFE:
        buf = await reader.readexactly(4)
        return struct.unpack('!I', buf)[0]
    else:
        buf = await reader.readexactly(8)
        return struct.unpack('!Q', buf)[0]
