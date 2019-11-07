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
import string
from ..tlv_type import BinaryStr
from ..tlv_var import write_tl_num, pack_uint_bytes, parse_tl_num, get_tl_num_size

CHARSET = (set(string.ascii_letters)
           | set(string.digits)
           | {'-', '.', '_', '~', '=', '%'})
TYPE_INVALID = 0x00
TYPE_GENERIC = 0x08
TYPE_IMPLICIT_SHA256 = 0x01
TYPE_PARAMETERS_SHA256 = 0x02
TYPE_KEYWORD = 0x20
TYPE_SEGMENT = 0x21
TYPE_BYTE_OFFSET = 0x22
TYPE_VERSION = 0x23
TYPE_TIMESTAMP = 0x24
TYPE_SEQUENCE_NUM = 0x25


def from_bytes(val: BinaryStr, typ: int = TYPE_GENERIC) -> bytearray:
    size_typ = get_tl_num_size(typ)
    size_len = get_tl_num_size(len(val))
    ret = bytearray(size_typ + size_len + len(val))
    write_tl_num(typ, ret, 0)
    write_tl_num(len(val), ret, size_typ)
    ret[size_typ+size_len:] = val
    return ret


def from_hex(val: str, typ: int = TYPE_GENERIC) -> bytearray:
    return from_bytes(bytearray.fromhex(val), typ)


def from_str(val: str) -> bytearray:
    def raise_except():
        raise ValueError(f'{val} is not a legal Name.')

    # Check empty string
    if not val:
        return bytearray(b'\x08\x00')

    percent_cnt = 0
    type_offset = None
    # Check charset
    for i, ch in enumerate(val):
        if ch not in CHARSET:
            raise_except()
        if ch == '%':
            percent_cnt += 1
        if ch == "=":
            if type_offset is not None:
                raise_except()
            else:
                type_offset = i
    # Get Type
    typ = TYPE_GENERIC
    if type_offset is not None:
        try:
            typ_str = val[:type_offset]
            # Check special case
            if typ_str == 'sha256digest':
                return from_bytes(bytearray.fromhex(val[type_offset + 1:]), TYPE_IMPLICIT_SHA256)
            elif typ_str == 'params-sha256':
                return from_bytes(bytearray.fromhex(val[type_offset + 1:]), TYPE_PARAMETERS_SHA256)
            # General case
            else:
                typ = int(typ_str)
        except ValueError:
            raise_except()
    else:
        typ = TYPE_GENERIC
        type_offset = -1
    # Alloc buf
    length = len(val) - type_offset - 1 - 2 * percent_cnt
    if length < 0:
        raise_except()
    size_typ = get_tl_num_size(typ)
    size_len = get_tl_num_size(length)
    ret = bytearray(size_typ + size_len + length)
    view = memoryview(ret)
    write_tl_num(typ, ret, 0)
    write_tl_num(length, ret, size_typ)

    # Encode val
    i = type_offset + 1
    pos = size_typ + size_len

    def encode():
        if val[i] != '%':
            view[pos] = val[i].encode('utf-8')[0]
            return 1
        else:
            view[pos] = int(val[i+1:i+3], 16)
            return 3

    while i < len(val):
        try:
            i += encode()
            pos += 1
        except IndexError:
            raise_except()
    return ret


def from_number(val: int, typ: int) -> bytearray:
    return from_bytes(pack_uint_bytes(val), typ)


def from_segment(segment: int) -> bytearray:
    return from_number(segment, TYPE_SEGMENT)


def from_byte_offset(offset: int) -> bytearray:
    return from_number(offset, TYPE_BYTE_OFFSET)


def from_sequence_num(seq_num: int) -> bytearray:
    return from_number(seq_num, TYPE_SEQUENCE_NUM)


def from_version(version: int) -> bytearray:
    return from_number(version, TYPE_VERSION)


def from_timestamp(timestamp: int) -> bytearray:
    return from_number(timestamp, TYPE_TIMESTAMP)


def get_type(component: BinaryStr) -> int:
    return parse_tl_num(component)[0]


def get_value(component: BinaryStr) -> memoryview:
    _, size_typ = parse_tl_num(component, 0)
    _, size_len = parse_tl_num(component, size_typ)
    return memoryview(component)[size_typ + size_len:]


def to_str(component: BinaryStr) -> str:
    offset = 0
    typ, sz = parse_tl_num(component, offset)
    offset += sz
    length, sz = parse_tl_num(component, offset)
    offset += sz
    if len(component) != length + offset:
        raise ValueError(f'{component} is malformed.')

    if typ == TYPE_IMPLICIT_SHA256:
        return f"sha256digest={component[offset:].hex()}"
    elif typ == TYPE_PARAMETERS_SHA256:
        return f"params-sha256={component[offset:].hex()}"
    else:
        ret = ""
        if typ != TYPE_GENERIC:
            ret = f"{typ}="

        def decode(val: int) -> str:
            ret = chr(val)
            if ret in CHARSET and ret not in {'%', '='}:
                return ret
            else:
                return f"%{val:02X}"

        return ret + "".join(decode(val) for val in component[offset:])


def to_number(component: BinaryStr) -> int:
    _, size_typ = parse_tl_num(component, 0)
    _, size_len = parse_tl_num(component, size_typ)
    return int.from_bytes(component[size_typ + size_len:], 'big')


def escape_str(val: str) -> str:
    def escape_chr(ch):
        if ch in CHARSET:
            return ch
        else:
            return f'%{ord(ch):02x}'

    return ''.join(escape_chr(ch) for ch in val)
