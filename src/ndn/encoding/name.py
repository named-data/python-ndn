from .tlv_var import *
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
    def from_str(val: str) -> bytearray:
        def raise_except():
            raise ValueError(f'{val} is not a legal Name.')

        percent_cnt = 0
        type_offset = None
        # Check charset
        for i, ch in enumerate(val):
            if ch not in Component.CHARSET:
                raise_except()
            if ch == '%':
                percent_cnt += 1
            if ch == "=":
                if type_offset:
                    raise_except()
                else:
                    type_offset = i
        # Get Type
        typ = Component.TYPE_GENERIC
        if type_offset:
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
        if length <= 2:
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
            except ValueError:
                raise_except()
        return ret

    @staticmethod
    def from_segment(segment: int) -> bytearray:
        return Component.from_bytes(pack_uint_bytes(segment), Component.TYPE_SEGMENT)

    @staticmethod
    def from_byte_offset(segment: int) -> bytearray:
        return Component.from_bytes(pack_uint_bytes(segment), Component.TYPE_BYTE_OFFSET)

    @staticmethod
    def from_sequence_num(seq_num: int) -> bytearray:
        return Component.from_bytes(pack_uint_bytes(seq_num), Component.TYPE_SEQUENCE_NUM)

    @staticmethod
    def from_version(version: int) -> bytearray:
        return Component.from_bytes(pack_uint_bytes(version), Component.TYPE_VERSION)

    @staticmethod
    def from_timestamp(timestamp: int) -> bytearray:
        return Component.from_bytes(pack_uint_bytes(timestamp), Component.TYPE_TIMESTAMP)

    @staticmethod
    def get_type(component: BinaryStr) -> int:
        return parse_tl_num(component)[0]

    @staticmethod
    def to_uri(component: BinaryStr) -> str:
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
                if ret in Component.CHARSET:
                    return ret
                else:
                    return f"%{hex(val)[2:]}"

            return ret + "".join(decode(val) for val in component[offset:])

    @staticmethod
    def to_number(component: BinaryStr) -> int:
        _, sz = parse_tl_num(component)
        return int.from_bytes(component[sz:], 'big')

    @staticmethod
    def to_bytes(component: BinaryStr) -> memoryview:
        _, sz = parse_tl_num(component)
        return memoryview(component)[sz:]


class Name:
    pass
