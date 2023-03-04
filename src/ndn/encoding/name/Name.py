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
"""
Name module is a collection of functions processing NDN Names.
"""
from functools import reduce
from typing import List, Optional, Iterable
from . import Component
from ..tlv_type import BinaryStr, VarBinaryStr, FormalName, NonStrictName, is_binary_str
from ..tlv_var import write_tl_num, parse_tl_num, get_tl_num_size


TYPE_NAME = 0x07
"""The TLV type of NDN Name."""


def from_str(val: str) -> List[bytearray]:
    r"""
    Construct a Name from a URI string.

    :param val: URI string. Character out of :const:`ndn.encoding.name.Component.CHARSET` will be
        escaped automatically. Leading and tailing ``'/'`` will be removed.

        .. note::
            Additional periods are not allowed here. To create a zero-size Component, use two slashes
            to surround it. Also, there should be no scheme identifier and authority component in the
            URI.

    :return: :any:`FormalName`.

    :examples:
        >>> from ndn.encoding.name import Name
        >>> Name.from_str("example/name")
        [bytearray(b'\x08\x07example'), bytearray(b'\x08\x04name')]

        >>> Name.from_str("/a//32=b/")
        [bytearray(b'\x08\x01a'), bytearray(b'\x08\x00'), bytearray(b'\x20\x01b')]

        >>> Name.from_str('/a/../b')
        [bytearray(b'\x08\x01a'), bytearray(b'\x08\x02..'), bytearray(b'\x08\x01b')]
    """
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


def to_str(name: NonStrictName) -> str:
    r"""
    Convert an NDN Name to a URI string.

    :param name: the input NDN Name.
    :type name: :any:`NonStrictName`
    :return: the URI.

    :examples:
        >>> from ndn.encoding.name import Name
        >>> Name.to_str('Σπυρίδων')
        '/%CE%A3%CF%80%CF%85%CF%81%CE%AF%CE%B4%CF%89%CE%BD'
    """
    name = normalize(name)
    ret = '/' + '/'.join(Component.to_str(comp) for comp in name)
    if name and name[-1] == b'\x08\x00':
        ret += '/'
    return ret


def to_canonical_uri(name: NonStrictName) -> str:
    r"""
    Convert an NDN Name to a canonical URI string without naming conventions.

    :param name: the input NDN Name.
    :type name: :any:`NonStrictName`
    :return: the canonical URI.

    :examples:
        >>> from ndn.encoding.name import Name
        >>> Name.to_canonical_uri('Σπυρίδων')
        '/%CE%A3%CF%80%CF%85%CF%81%CE%AF%CE%B4%CF%89%CE%BD'
    """
    name = normalize(name)
    ret = '/' + '/'.join(Component.to_canonical_uri(comp) for comp in name)
    if name and name[-1] == b'\x08\x00':
        ret += '/'
    return ret


def from_bytes(buf: BinaryStr) -> FormalName:
    r"""
    Decode the Name from its TLV encoded form.

    :param buf: encoded Name.
    :return: Decoded Name.
    :rtype: :any:`FormalName`

    :raises ValueError: if the Type is not :any:`TYPE_NAME` .
    """
    return decode(buf)[0]


def to_bytes(name: NonStrictName) -> bytes:
    r"""
    Encode a Name via TLV encoding.

    :param name: Name to encode.
    :type name: :any:`NonStrictName`
    :return: Encoded Name.
    """
    if not is_binary_str(name):
        name = encode(normalize(name))
    return bytes(name)


def is_prefix(lhs: NonStrictName, rhs: NonStrictName) -> bool:
    r"""
    Test if a Name is a prefix of another Name.

    :param lhs: prefix to be tested.
    :type lhs: :any:`NonStrictName`
    :param rhs: full name to test on.
    :type rhs: :any:`NonStrictName`
    :return: ``True`` if ``lhs`` is a prefix of ``rhs``.
    """
    lhs = normalize(lhs)
    rhs = normalize(rhs)
    left_len = len(lhs)
    return left_len <= len(rhs) and lhs == rhs[:left_len]


def encoded_length(name: FormalName) -> int:
    length = reduce(lambda x, y: x + len(y), name, 0)
    size_typ = 1
    size_len = get_tl_num_size(length)
    return length + size_typ + size_len


def encode(name: FormalName, buf: Optional[VarBinaryStr] = None, offset: int = 0) -> VarBinaryStr:
    length = reduce(lambda x, y: x + len(y), name, 0)
    size_typ = 1
    size_len = get_tl_num_size(length)

    if not buf:
        buf = bytearray(length + size_typ + size_len)
    else:
        if len(buf) < length + size_typ + size_len + offset:
            raise IndexError('buffer overflow')

    offset += write_tl_num(TYPE_NAME, buf, offset)
    offset += write_tl_num(length, buf, offset)
    for comp in name:
        buf[offset:offset+len(comp)] = comp
        offset += len(comp)
    return buf


def decode(buf: BinaryStr, offset: int = 0) -> (List[memoryview], int):
    buf = memoryview(buf)
    origin_offset = offset

    typ, size_typ = parse_tl_num(buf, offset)
    offset += size_typ
    if typ != TYPE_NAME:
        raise ValueError(f'the Type of {buf} is not Name')

    length, size_len = parse_tl_num(buf, offset)
    offset += size_len
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


def normalize(name: NonStrictName) -> FormalName:
    r"""
    Convert a NonStrictName to a FormalName.
    If name is a binary string, decode it.
    If name is a str, encode it into FormalName.
    If name is a list, encode all str elements into Components.

    :param name: the NonStrictName.
    :type name: :any:`NonStrictName`
    :return: the FormalName. It may be a swallow copy of name.
    :rtype: :any:`FormalName`

    :raises TypeError: if the name or one of its element has a unrecognized type.

    :examples:
        >>> from ndn.encoding.name import Name
        >>> Name.normalize(f'{i}' for i in range(3))
        [bytearray(b'\x08\x010'), bytearray(b'\x08\x011'), bytearray(b'\x08\x012')]

        >>> Name.normalize(['Алек', b'%\x01\x00'])
        [bytearray(b'\x08\x08\xd0\x90\xd0\xbb\xd0\xb5\xd0\xba'), b'%\x01\x00']
    """
    if is_binary_str(name):
        return decode(name)[0]
    elif isinstance(name, str):
        return from_str(name)
    elif not isinstance(name, Iterable):
        raise TypeError('invalid type for name')
    ret = list(name)
    for i, comp in enumerate(ret):
        if isinstance(comp, str):
            ret[i] = Component.from_str(Component.escape_str(comp))
        elif not is_binary_str(comp):
            raise TypeError('invalid type for name component')
    return ret
