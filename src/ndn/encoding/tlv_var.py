# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
import struct
import asyncio as aio
from .tlv_type import BinaryStr, VarBinaryStr


__all__ = ['get_tl_num_size', 'write_tl_num', 'pack_uint_bytes', 'parse_tl_num', 'read_tl_num_from_stream',
           'parse_and_check_tl']


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


def parse_and_check_tl(wire: BinaryStr, expected_type: int) -> memoryview:
    typ, typ_len = parse_tl_num(wire, 0)
    size, siz_len = parse_tl_num(wire, typ_len)
    if typ != expected_type:
        raise ValueError(f'wire is of type {typ} but {expected_type} is expected')
    if len(wire) != typ_len+siz_len+size:
        raise IndexError(f'wire size {len(wire)} mismatch with object size {size}')
    return memoryview(wire)[typ_len+siz_len:typ_len+siz_len+size]
