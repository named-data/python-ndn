from typing import List, Optional
from .tlv_var import *
from functools import reduce
import string


class Component:
    CHARSET = (
        set(string.ascii_letters) |
        set(string.digits) |
        {'-', '.', '_', '~', '=', '%'})
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

    @staticmethod
    def from_bytes(val: BinaryStr, typ: int = TYPE_GENERIC) -> bytearray:
        # Currently it's impossible for TL to be >65535
        size_typ = 1 if typ < 253 else 3
        size_len = 1 if len(val) < 253 else 3
        ret = bytearray(size_typ + size_len + len(val))
        write_tl_num(typ, ret, 0)
        write_tl_num(len(val), ret, size_typ)
        ret[size_typ + size_len:] = val
        return ret

    @staticmethod
    def from_hex(val: str, typ: int = TYPE_GENERIC) -> bytearray:
        return Component.from_bytes(bytearray.fromhex(val), typ)

    @staticmethod
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
            if ch not in Component.CHARSET:
                raise_except()
            if ch == '%':
                percent_cnt += 1
            if ch == "=":
                if type_offset is not None:
                    raise_except()
                else:
                    type_offset = i
        # Get Type
        typ = Component.TYPE_GENERIC
        if type_offset is not None:
            try:
                typ_str = val[:type_offset]
                # Check special case
                if typ_str == 'sha256digest':
                    return Component.from_bytes(
                        bytearray.fromhex(val[type_offset + 1:]),
                        Component.TYPE_IMPLICIT_SHA256)
                elif typ_str == 'params-sha256':
                    return Component.from_bytes(
                        bytearray.fromhex(val[type_offset + 1:]),
                        Component.TYPE_PARAMETERS_SHA256)
                # General case
                else:
                    typ = int(typ_str)
            except ValueError:
                raise_except()
        else:
            typ = Component.TYPE_GENERIC
            type_offset = -1
        # Alloc buf
        length = len(val) - type_offset - 1 - 2 * percent_cnt
        if length < 0:
            raise_except()
        size_typ = 1 if typ < 253 else 3
        size_len = 1 if length < 253 else 3
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

    @staticmethod
    def from_number(val: int, typ: int) -> bytearray:
        return Component.from_bytes(pack_uint_bytes(val), typ)

    @staticmethod
    def from_segment(segment: int) -> bytearray:
        return Component.from_number(segment, Component.TYPE_SEGMENT)

    @staticmethod
    def from_byte_offset(offset: int) -> bytearray:
        return Component.from_number(offset, Component.TYPE_BYTE_OFFSET)

    @staticmethod
    def from_sequence_num(seq_num: int) -> bytearray:
        return Component.from_number(seq_num, Component.TYPE_SEQUENCE_NUM)

    @staticmethod
    def from_version(version: int) -> bytearray:
        return Component.from_number(version, Component.TYPE_VERSION)

    @staticmethod
    def from_timestamp(timestamp: int) -> bytearray:
        return Component.from_number(timestamp, Component.TYPE_TIMESTAMP)

    @staticmethod
    def get_type(component: BinaryStr) -> int:
        return parse_tl_num(component)[0]

    @staticmethod
    def get_value(component: BinaryStr) -> memoryview:
        _, size_typ = parse_tl_num(component)
        _, size_len = parse_tl_num(component)
        return memoryview(component)[size_typ + size_len:]

    @staticmethod
    def to_str(component: BinaryStr) -> str:
        offset = 0
        typ, sz = parse_tl_num(component, offset)
        offset += sz
        length, sz = parse_tl_num(component, offset)
        offset += sz
        if len(component) != length + offset:
            raise ValueError(f'{component} is malformed.')

        if typ == Component.TYPE_IMPLICIT_SHA256:
            return f"sha256digest={component[offset:].hex()}"
        elif typ == Component.TYPE_PARAMETERS_SHA256:
            return f"params-sha256={component[offset:].hex()}"
        else:
            ret = ""
            if typ != Component.TYPE_GENERIC:
                ret = f"{typ}="

            def decode(val: int) -> str:
                ret = chr(val)
                if ret in Component.CHARSET and ret not in {'%', '='}:
                    return ret
                else:
                    return f"%{val:02x}"

            return ret + "".join(decode(val) for val in component[offset:])

    @staticmethod
    def to_number(component: BinaryStr) -> int:
        _, size_typ = parse_tl_num(component)
        _, size_len = parse_tl_num(component)
        return int.from_bytes(component[size_typ + size_len:], 'big')

    @staticmethod
    def escape_str(val: str) -> str:
        def escape_chr(ch):
            if ch in Component.CHARSET:
                return ch
            else:
                return f'%{ord(ch):02x}'

        return ''.join(escape_chr(ch) for ch in val)


class Name:
    TYPE_NAME = 7

    @staticmethod
    def from_str(val: str) -> List[bytearray]:
        # TODO: declare the differences: ":" and "."
        # Remove leading and tailing '/'
        cnt_slash = 0
        if val.startswith('/'):
            val = val[1:]
            cnt_slash += 1
        if val.endswith('/'):
            val = val[:-1]
            cnt_slash += 1
        if not val and cnt_slash <= 1:
            return []
        compstrs = val.split('/')
        return [Component.from_str(Component.escape_str(comp)) for comp in compstrs]

    @staticmethod
    def to_str(name: List[BinaryStr]) -> str:
        return '/' + '/'.join(Component.to_str(comp) for comp in name)

    @staticmethod
    def is_prefix(lhs: List[BinaryStr], rhs: List[BinaryStr]) -> bool:
        left_len = len(lhs)
        return left_len <= len(rhs) and lhs == rhs[:left_len]

    @staticmethod
    def encoded_length(name: List[BinaryStr]) -> int:
        size_val = reduce(lambda x, y: x + len(y), name, 0)
        size_typ = 1
        size_len = 1 if size_val < 253 else 3
        return size_val + size_typ + size_len

    @staticmethod
    def encode(name: List[BinaryStr], buf: Optional[VarBinaryStr] = None, offset: int = 0) -> VarBinaryStr:
        size_val = reduce(lambda x, y: x + len(y), name, 0)
        size_typ = 1
        size_len = 1 if size_val < 253 else 3

        if not buf:
            buf = bytearray(size_val + size_typ + size_len)
        else:
            if len(buf) < size_val + size_typ + size_len + offset:
                raise IndexError('buffer overflow')

        offset += write_tl_num(Name.TYPE_NAME, buf, offset)
        offset += write_tl_num(size_val, buf, offset)
        for comp in name:
            buf[offset:offset+len(comp)] = comp
            offset += len(comp)
        return buf

    @staticmethod
    def decode(buf: BinaryStr, offset: int = 0) -> (List[memoryview], int):
        buf = memoryview(buf)
        origin_offset = offset

        typ, size_typ = parse_tl_num(buf, offset)
        offset += size_typ
        if typ != Name.TYPE_NAME:
            raise ValueError(f'the Type of {buf} is not Name')

        length, size_len = parse_tl_num(buf, offset)
        offset += size_typ
        if length > len(buf) - offset:
            raise IndexError('buffer overflow')

        ret = []
        while length > 0:
            st = offset
            _, size_typ_comp = parse_tl_num(buf, offset)
            offset += size_typ_comp
            len_comp, size_len_comp = parse_tl_num(buf, offset)
            offset += size_len_comp + len_comp
            ret.append(buf[st:offset])
            length -= (offset - st)

        return ret, offset - origin_offset
