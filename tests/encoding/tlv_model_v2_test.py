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
"""Tests for the dataclass-based TLV v2 API (tlv_encode / tlv_parse)."""
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag
from typing import Dict, List, Optional

import pytest

from ndn.encoding import (
    tlv_encode, tlv_parse, NDNName, DecodeError,
    # v1 equivalents used for binary-compatibility checks
    TlvModel, UintField, BoolField, BytesField, NameField, ModelField,
    RepeatedField, Name, Component,
)


# ---------------------------------------------------------------------------
# Shared dataclass fixtures (defined at module scope for get_type_hints)
# ---------------------------------------------------------------------------

@dataclass
class _Inner:
    val: int = field(default=None, metadata={'tlv_type': 0x01})


@dataclass
class _Outer:
    inner: _Inner = field(default=None, metadata={'tlv_type': 0x02})


@dataclass
class _RepeatedUint:
    words: List[int] = field(default_factory=list,
                              metadata={'tlv_type': 0x01, 'fixed_len': 2})


@dataclass
class _RepeatedModel:
    items: List[_Inner] = field(default_factory=list, metadata={'tlv_type': 0x10})


# ---------------------------------------------------------------------------
# TestUintField
# ---------------------------------------------------------------------------

class TestUintField:
    """UintField: variable-width and fixed-width non-negative integers."""

    def test_min_width_1_byte(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})

        obj = M(x=0)
        wire = tlv_encode(obj)
        assert wire == b'\x03\x01\x00'
        assert tlv_parse(M, wire).x == 0

    def test_min_width_2_bytes(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})

        obj = M(x=0x0100)
        wire = tlv_encode(obj)
        assert wire == b'\x03\x02\x01\x00'
        assert tlv_parse(M, wire).x == 0x0100

    def test_min_width_4_bytes(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})

        obj = M(x=0x00010000)
        wire = tlv_encode(obj)
        assert wire == b'\x03\x04\x00\x01\x00\x00'
        assert tlv_parse(M, wire).x == 0x00010000

    def test_min_width_8_bytes(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})

        obj = M(x=0x0000000100000000)
        wire = tlv_encode(obj)
        assert wire == b'\x03\x08\x00\x00\x00\x01\x00\x00\x00\x00'
        assert tlv_parse(M, wire).x == 0x0000000100000000

    def test_fixed_len_1(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x1b, 'fixed_len': 1})

        obj = M(x=3)
        wire = tlv_encode(obj)
        # T=0x1b L=0x01 V=0x03
        assert wire == b'\x1b\x01\x03'
        assert tlv_parse(M, wire).x == 3

    def test_fixed_len_2(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03, 'fixed_len': 2})

        obj = M(x=5)
        wire = tlv_encode(obj)
        assert wire == b'\x03\x02\x00\x05'
        assert tlv_parse(M, wire).x == 5

    def test_none_omitted(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})
            y: int = field(default=None, metadata={'tlv_type': 0x05})

        wire = tlv_encode(M(x=None, y=7))
        assert wire == b'\x05\x01\x07'
        p = tlv_parse(M, wire)
        assert p.x is None
        assert p.y == 7

    def test_optional_annotation(self):
        @dataclass
        class M:
            x: Optional[int] = field(default=None, metadata={'tlv_type': 0x03})

        obj = M(x=42)
        wire = tlv_encode(obj)
        assert tlv_parse(M, wire).x == 42


class TestUintFieldEnum:
    """IntEnum and IntFlag auto-conversion on parse."""

    def test_intenum_roundtrip(self):
        class FaceType(IntEnum):
            PERSISTENT = 1
            ON_DEMAND  = 2

        @dataclass
        class M:
            face_type: FaceType = field(default=None, metadata={'tlv_type': 0x84})

        obj = M(face_type=FaceType.PERSISTENT)
        wire = tlv_encode(obj)
        p = tlv_parse(M, wire)
        assert p.face_type == FaceType.PERSISTENT
        assert isinstance(p.face_type, FaceType)

    def test_intflag_roundtrip(self):
        class Flags(IntFlag):
            A = 1
            B = 2

        @dataclass
        class M:
            f: Flags = field(default=None, metadata={'tlv_type': 0x06})

        obj = M(f=Flags.A | Flags.B)
        wire = tlv_encode(obj)
        p = tlv_parse(M, wire)
        assert p.f == Flags.A | Flags.B
        assert isinstance(p.f, Flags)

    def test_unknown_enum_value_returns_int(self):
        class Color(IntEnum):
            RED = 1

        @dataclass
        class M:
            c: Color = field(default=None, metadata={'tlv_type': 0x01})

        # Wire with value 99, which is not a valid Color
        wire = b'\x01\x01\x63'
        p = tlv_parse(M, wire)
        assert p.c == 99
        assert type(p.c) is int


# ---------------------------------------------------------------------------
# TestBoolField
# ---------------------------------------------------------------------------

class TestBoolField:
    """BoolField: 0-length TLV present when truthy, absent otherwise."""

    def test_present(self):
        @dataclass
        class M:
            flag: bool = field(default=None, metadata={'tlv_type': 0x12})

        wire = tlv_encode(M(flag=True))
        # T=0x12 L=0x00
        assert wire == b'\x12\x00'
        assert tlv_parse(M, wire).flag is True

    def test_absent_when_false(self):
        @dataclass
        class M:
            flag: bool = field(default=None, metadata={'tlv_type': 0x12})

        assert tlv_encode(M(flag=False)) == b''
        assert tlv_encode(M(flag=None))  == b''

    def test_absent_field_returns_none(self):
        @dataclass
        class M:
            flag: bool = field(default=None, metadata={'tlv_type': 0x12})
            x:    int  = field(default=None, metadata={'tlv_type': 0x14})

        wire = tlv_encode(M(flag=None, x=1))
        p = tlv_parse(M, wire)
        assert p.flag is None
        assert p.x == 1

    def test_optional_annotation(self):
        @dataclass
        class M:
            flag: Optional[bool] = field(default=None, metadata={'tlv_type': 0x12})

        wire = tlv_encode(M(flag=True))
        assert tlv_parse(M, wire).flag is True


# ---------------------------------------------------------------------------
# TestBytesField
# ---------------------------------------------------------------------------

class TestBytesField:
    """BytesField: raw bytes and UTF-8 strings."""

    def test_bytes_roundtrip(self):
        @dataclass
        class M:
            data: bytes = field(default=None, metadata={'tlv_type': 0x15})

        obj = M(data=b'\x01\x02\x03')
        wire = tlv_encode(obj)
        assert wire == b'\x15\x03\x01\x02\x03'
        p = tlv_parse(M, wire)
        assert bytes(p.data) == b'\x01\x02\x03'

    def test_bytes_parse_is_memoryview(self):
        @dataclass
        class M:
            data: bytes = field(default=None, metadata={'tlv_type': 0x15})

        wire = b'\x15\x02\xde\xad'
        p = tlv_parse(M, wire)
        assert isinstance(p.data, memoryview)

    def test_str_field_roundtrip(self):
        @dataclass
        class M:
            label: str = field(default=None, metadata={'tlv_type': 0x16})

        obj = M(label='hello')
        wire = tlv_encode(obj)
        assert wire == b'\x16\x05hello'
        assert tlv_parse(M, wire).label == 'hello'

    def test_str_field_unicode(self):
        @dataclass
        class M:
            s: str = field(default=None, metadata={'tlv_type': 0x16})

        obj = M(s='日本語')
        wire = tlv_encode(obj)
        assert tlv_parse(M, wire).s == '日本語'

    def test_bytearray_annotation(self):
        @dataclass
        class M:
            data: bytearray = field(default=None, metadata={'tlv_type': 0x15})

        wire = tlv_encode(M(data=bytearray(b'abc')))
        p = tlv_parse(M, wire)
        assert bytes(p.data) == b'abc'

    def test_memoryview_annotation(self):
        @dataclass
        class M:
            data: memoryview = field(default=None, metadata={'tlv_type': 0x15})

        src = bytearray(b'\xca\xfe')
        wire = tlv_encode(M(data=memoryview(src)))
        p = tlv_parse(M, wire)
        assert isinstance(p.data, memoryview)
        assert bytes(p.data) == b'\xca\xfe'

    def test_large_value_multibyte_length(self):
        """Length field uses multi-byte varint when value ≥ 253 bytes."""
        @dataclass
        class M:
            data: bytes = field(default=None, metadata={'tlv_type': 0x15})

        payload = bytes(range(256))
        wire = tlv_encode(M(data=payload))
        # Length 256 → encoded as 0xFD 0x01 0x00 (3 bytes)
        assert wire[1:4] == b'\xfd\x01\x00'
        p = tlv_parse(M, wire)
        assert bytes(p.data) == payload


# ---------------------------------------------------------------------------
# TestNameField
# ---------------------------------------------------------------------------

class TestNameField:
    """NDNName: NDN Name TLV via string, FormalName list, or binary."""

    def test_from_string(self):
        @dataclass
        class M:
            name: NDNName = field(default=None, metadata={'tlv_type': 0x07})

        obj = M(name='/foo/bar')
        wire = tlv_encode(obj)
        # 0x07 0x0a [0x08 0x03 foo] [0x08 0x03 bar]
        assert wire == b'\x07\x0a\x08\x03foo\x08\x03bar'
        p = tlv_parse(M, wire)
        assert Name.to_str(p.name) == '/foo/bar'

    def test_from_formal_name(self):
        @dataclass
        class M:
            name: NDNName = field(default=None, metadata={'tlv_type': 0x07})

        formal = Name.from_str('/a/b')
        wire = tlv_encode(M(name=formal))
        p = tlv_parse(M, wire)
        assert Name.to_str(p.name) == '/a/b'

    def test_empty_name(self):
        @dataclass
        class M:
            name: NDNName = field(default=None, metadata={'tlv_type': 0x07})

        wire = tlv_encode(M(name='/'))
        p = tlv_parse(M, wire)
        assert p.name == []

    def test_none_omitted(self):
        @dataclass
        class M:
            name: NDNName = field(default=None, metadata={'tlv_type': 0x07})

        assert tlv_encode(M(name=None)) == b''

    def test_repeated_names(self):
        """List[NDNName] — multiple Name TLVs with the same type number."""
        @dataclass
        class M:
            names: List[NDNName] = field(default_factory=list,
                                          metadata={'tlv_type': 0x07})

        obj = M(names=['/foo', '/bar'])
        wire = tlv_encode(obj)
        p = tlv_parse(M, wire)
        assert len(p.names) == 2
        assert Name.to_str(p.names[0]) == '/foo'
        assert Name.to_str(p.names[1]) == '/bar'


# ---------------------------------------------------------------------------
# TestModelField
# ---------------------------------------------------------------------------

class TestModelField:
    """ModelField: nested dataclass, recursively encoded."""

    def test_basic_nested(self):
        wire = tlv_encode(_Outer(inner=_Inner(val=255)))
        # 0x02 (outer T) 0x03 (outer L) 0x01 0x01 0xFF
        assert wire == b'\x02\x03\x01\x01\xff'
        p = tlv_parse(_Outer, wire)
        assert p.inner.val == 255

    def test_absent_nested(self):
        wire = tlv_encode(_Outer(inner=None))
        assert wire == b''
        p = tlv_parse(_Outer, wire)
        assert p.inner is None

    def test_deeply_nested(self):
        @dataclass
        class Level3:
            x: int = field(default=None, metadata={'tlv_type': 0x01})

        @dataclass
        class Level2:
            sub: Level3 = field(default=None, metadata={'tlv_type': 0x10})

        @dataclass
        class Level1:
            sub: Level2 = field(default=None, metadata={'tlv_type': 0x20})

        obj = Level1(sub=Level2(sub=Level3(x=7)))
        wire = tlv_encode(obj)
        p = tlv_parse(Level1, wire)
        assert p.sub.sub.x == 7

    def test_ignore_critical_propagated(self):
        """ignore_critical in metadata is forwarded to nested parse."""
        @dataclass
        class Inner:
            x: int = field(default=None, metadata={'tlv_type': 0x01})

        @dataclass
        class Outer:
            sub: Inner = field(default=None,
                               metadata={'tlv_type': 0x10,
                                         'ignore_critical': True})

        # Inject an unknown critical TLV (type 0x03, odd) inside sub
        inner_wire = b'\x03\x01\x00'
        sub_wire = bytes([0x10, len(inner_wire)]) + inner_wire
        # With ignore_critical via metadata, this must not raise
        p = tlv_parse(Outer, sub_wire)
        assert p.sub.x is None


# ---------------------------------------------------------------------------
# TestRepeatedField
# ---------------------------------------------------------------------------

class TestRepeatedField:
    """RepeatedField: multiple TLVs of the same type, no outer wrapper."""

    def test_uint_elements(self):
        wire = tlv_encode(_RepeatedUint(words=[0, 1, 2]))
        # Each word: T=0x01 L=0x02 V=2-byte big-endian
        assert wire == b'\x01\x02\x00\x00\x01\x02\x00\x01\x01\x02\x00\x02'
        p = tlv_parse(_RepeatedUint, wire)
        assert p.words == [0, 1, 2]

    def test_bytes_elements(self):
        @dataclass
        class M:
            tags: List[bytes] = field(default_factory=list,
                                       metadata={'tlv_type': 0x17})

        obj = M(tags=[b'a', b'bb', b'ccc'])
        wire = tlv_encode(obj)
        assert wire == b'\x17\x01a\x17\x02bb\x17\x03ccc'
        p = tlv_parse(M, wire)
        assert [bytes(t) for t in p.tags] == [b'a', b'bb', b'ccc']

    def test_str_elements(self):
        @dataclass
        class M:
            labels: List[str] = field(default_factory=list,
                                       metadata={'tlv_type': 0x16})

        obj = M(labels=['hello', 'world'])
        wire = tlv_encode(obj)
        p = tlv_parse(M, wire)
        assert p.labels == ['hello', 'world']

    def test_model_elements(self):
        wire = tlv_encode(_RepeatedModel(items=[_Inner(val=10), _Inner(val=20)]))
        p = tlv_parse(_RepeatedModel, wire)
        assert [i.val for i in p.items] == [10, 20]

    def test_empty_list_produces_no_bytes(self):
        wire = tlv_encode(_RepeatedUint(words=[]))
        assert wire == b''

    def test_default_factory_list_initialised_on_parse(self):
        """A repeated field with no default_factory should still get a list on parse."""
        @dataclass
        class M:
            items: List[int] = field(metadata={'tlv_type': 0x05})

        wire = b'\x05\x01\x01\x05\x01\x02'
        p = tlv_parse(M, wire)
        assert p.items == [1, 2]


# ---------------------------------------------------------------------------
# TestOrdering
# ---------------------------------------------------------------------------

class TestOrdering:
    """NDN TLV ordering rules: forward-only matching, critical type handling."""

    def test_unknown_even_type_skipped(self):
        """Unknown even TLV types are silently ignored (non-critical)."""
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x04})

        # Wire: unknown even type 0x02, then known type 0x04
        wire = b'\x02\x01\xff\x04\x01\x07'
        p = tlv_parse(M, wire)
        assert p.x == 7

    def test_unknown_odd_type_raises(self):
        """Unknown odd TLV types are critical — must raise DecodeError."""
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x04})

        wire = b'\x03\x01\x00\x04\x01\x07'
        with pytest.raises(DecodeError):
            tlv_parse(M, wire)

    def test_ignore_critical_suppresses_error(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x04})

        wire = b'\x03\x01\x00\x04\x01\x07'
        p = tlv_parse(M, wire, ignore_critical=True)
        assert p.x == 7

    def test_out_of_order_critical_field_raises(self):
        """
        A critical (odd type) field appearing out-of-order is unrecognised and
        must raise DecodeError.  Even types are non-critical and silently dropped.
        """
        @dataclass
        class M:
            a: int = field(default=None, metadata={'tlv_type': 0x03})  # odd = critical
            b: int = field(default=None, metadata={'tlv_type': 0x05})  # odd = critical

        # b (0x05) comes first; after matching it, field_pos advances past a (0x03).
        # The parser then sees 0x03 as unknown critical → DecodeError.
        wire = b'\x05\x01\x02\x03\x01\x01'
        with pytest.raises(DecodeError):
            tlv_parse(M, wire)

    def test_out_of_order_even_field_silently_dropped(self):
        """Even (non-critical) fields seen out-of-order are silently skipped."""
        @dataclass
        class M:
            a: int = field(default=None, metadata={'tlv_type': 0x02})  # even
            b: int = field(default=None, metadata={'tlv_type': 0x04})  # even

        # b before a — a is dropped silently (non-critical)
        wire = b'\x04\x01\x02\x02\x01\x01'
        p = tlv_parse(M, wire)
        assert p.b == 2
        assert p.a is None

    def test_out_of_order_non_critical_silently_skipped(self):
        @dataclass
        class M:
            a: int = field(default=None, metadata={'tlv_type': 0x04})  # even, non-critical when out of order
            b: int = field(default=None, metadata={'tlv_type': 0x06})

        # b before a — a is even so silently skipped
        wire = b'\x06\x01\x02\x04\x01\x01'
        p = tlv_parse(M, wire)
        assert p.b == 2
        assert p.a is None


# ---------------------------------------------------------------------------
# TestInheritance
# ---------------------------------------------------------------------------

class TestInheritance:
    """Dataclass inheritance: parent fields come first (no IncludeBase needed)."""

    def test_parent_fields_encoded_first(self):
        @dataclass
        class Base:
            x: int = field(default=None, metadata={'tlv_type': 0x01})

        @dataclass
        class Child(Base):
            y: int = field(default=None, metadata={'tlv_type': 0x03})

        wire = tlv_encode(Child(x=1, y=2))
        # x (0x01) must appear before y (0x03)
        assert wire == b'\x01\x01\x01\x03\x01\x02'
        p = tlv_parse(Child, wire)
        assert p.x == 1 and p.y == 2

    def test_child_only_fields(self):
        @dataclass
        class Base:
            x: int = field(default=None, metadata={'tlv_type': 0x01})

        @dataclass
        class Child(Base):
            y: int = field(default=None, metadata={'tlv_type': 0x03})

        wire = tlv_encode(Child(x=None, y=5))
        assert wire == b'\x03\x01\x05'
        p = tlv_parse(Child, wire)
        assert p.x is None
        assert p.y == 5

    def test_non_tlv_fields_ignored(self):
        """Fields without 'tlv_type' in metadata are silently skipped."""
        @dataclass
        class M:
            internal: str = field(default='ignored')   # no metadata
            x: int = field(default=None, metadata={'tlv_type': 0x01})

        wire = tlv_encode(M(internal='should_not_appear', x=42))
        assert wire == b'\x01\x01\x2a'
        p = tlv_parse(M, wire)
        assert p.x == 42


# ---------------------------------------------------------------------------
# TestZeroCopyAndInPlace
# ---------------------------------------------------------------------------

class TestZeroCopyAndInPlace:
    """Zero-copy memoryview slices and in-place buffer encoding."""

    def test_bytes_parse_shares_buffer(self):
        """Parsed bytes field is a memoryview slice — no copy."""
        @dataclass
        class M:
            data: bytes = field(default=None, metadata={'tlv_type': 0x15})

        wire = bytearray(b'\x15\x04\xde\xad\xbe\xef')
        p = tlv_parse(M, wire)
        assert isinstance(p.data, memoryview)
        assert bytes(p.data) == b'\xde\xad\xbe\xef'

    def test_inplace_encode_returns_memoryview(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})

        buf = bytearray(20)
        mv = tlv_encode(M(x=7), buf, offset=5)
        assert isinstance(mv, memoryview)
        assert bytes(mv) == b'\x03\x01\x07'
        # Bytes written at correct position
        assert buf[5:8] == b'\x03\x01\x07'
        # Surrounding bytes untouched
        assert buf[:5] == b'\x00' * 5
        assert buf[8:] == b'\x00' * 12

    def test_inplace_matches_standalone(self):
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x03})
            y: bytes = field(default=None, metadata={'tlv_type': 0x15})

        obj = M(x=300, y=b'hello')
        standalone = tlv_encode(obj)
        buf = bytearray(len(standalone) + 10)
        mv = tlv_encode(obj, buf, offset=3)
        assert bytes(mv) == bytes(standalone)

    def test_inplace_memoryview_buffer(self):
        """In-place encoding also works with a memoryview target."""
        @dataclass
        class M:
            x: int = field(default=None, metadata={'tlv_type': 0x05})

        buf = bytearray(10)
        mv_buf = memoryview(buf)
        result = tlv_encode(M(x=1), mv_buf, offset=2)
        assert bytes(result) == b'\x05\x01\x01'


# ---------------------------------------------------------------------------
# TestDefaultHandling
# ---------------------------------------------------------------------------

class TestDefaultHandling:
    """Default values and field initialisation during parse."""

    def test_field_with_explicit_default_preserved_if_absent(self):
        @dataclass
        class M:
            x: int = field(default=42, metadata={'tlv_type': 0x01})

        # Wire that does not contain field x
        wire = b''
        p = tlv_parse(M, wire)
        assert p.x == 42

    def test_field_without_default_is_none_if_absent(self):
        @dataclass
        class M:
            x: int = field(metadata={'tlv_type': 0x01})

        wire = b''
        p = tlv_parse(M, wire)
        assert p.x is None

    def test_default_factory_list_preserved_if_absent(self):
        wire = tlv_encode(_RepeatedUint(words=[]))
        p = tlv_parse(_RepeatedUint, wire)
        assert p.words == []


# ---------------------------------------------------------------------------
# TestBinaryCompatibility
# ---------------------------------------------------------------------------

class TestBinaryCompatibility:
    """Byte-for-byte compatibility with the v1 TlvModel metaclass API."""

    def test_uint_compat(self):
        class V1(TlvModel):
            sig_type = UintField(0x1b, fixed_len=1)
            nonce    = UintField(0x26)

        @dataclass
        class V2:
            sig_type: int = field(default=None,
                                   metadata={'tlv_type': 0x1b, 'fixed_len': 1})
            nonce:    int = field(default=None, metadata={'tlv_type': 0x26})

        v1 = V1(); v1.sig_type = 3; v1.nonce = 42
        assert bytes(v1.encode()) == bytes(tlv_encode(V2(sig_type=3, nonce=42)))

    def test_bool_compat(self):
        class V1(TlvModel):
            flag  = BoolField(0x12)
            count = UintField(0x0a)

        @dataclass
        class V2:
            flag:  bool = field(default=None, metadata={'tlv_type': 0x12})
            count: int  = field(default=None, metadata={'tlv_type': 0x0a})

        for flag_val in (True, False, None):
            v1 = V1(); v1.flag = flag_val; v1.count = 5
            v2 = V2(flag=flag_val, count=5)
            assert bytes(v1.encode()) == bytes(tlv_encode(v2))

    def test_bytes_compat(self):
        class V1(TlvModel):
            raw   = BytesField(0x15)
            label = BytesField(0x16, is_string=True)

        @dataclass
        class V2:
            raw:   bytes = field(default=None, metadata={'tlv_type': 0x15})
            label: str   = field(default=None, metadata={'tlv_type': 0x16})

        v1 = V1(); v1.raw = b'\x01\x02\x03'; v1.label = 'hi'
        v2 = V2(raw=b'\x01\x02\x03', label='hi')
        assert bytes(v1.encode()) == bytes(tlv_encode(v2))

    def test_name_compat(self):
        class V1(TlvModel):
            name = NameField()

        @dataclass
        class V2:
            name: NDNName = field(default=None, metadata={'tlv_type': 0x07})

        v1 = V1(); v1.name = '/foo/bar'
        v2 = V2(name='/foo/bar')
        assert bytes(v1.encode()) == bytes(tlv_encode(v2))

    def test_model_compat(self):
        class V1Inner(TlvModel):
            val = UintField(0x01)

        class V1Outer(TlvModel):
            inner = ModelField(0x10, V1Inner)

        @dataclass
        class V2Inner:
            val: int = field(default=None, metadata={'tlv_type': 0x01})

        @dataclass
        class V2Outer:
            inner: V2Inner = field(default=None, metadata={'tlv_type': 0x10})

        v1 = V1Outer(); v1.inner = V1Inner(); v1.inner.val = 99
        v2 = V2Outer(inner=V2Inner(val=99))
        assert bytes(v1.encode()) == bytes(tlv_encode(v2))

    def test_repeated_uint_compat(self):
        class V1(TlvModel):
            words = RepeatedField(UintField(0x01, fixed_len=2))

        v1 = V1(); v1.words = [0, 1, 2]
        v2 = _RepeatedUint(words=[0, 1, 2])
        assert bytes(v1.encode()) == bytes(tlv_encode(v2))

    def test_repeated_model_compat(self):
        class V1Inner(TlvModel):
            val = UintField(0x01)

        class V1Rep(TlvModel):
            items = RepeatedField(ModelField(0x10, V1Inner))

        v1 = V1Rep()
        r1 = V1Inner(); r1.val = 10
        r2 = V1Inner(); r2.val = 20
        v1.items = [r1, r2]

        v2 = _RepeatedModel(items=[_Inner(val=10), _Inner(val=20)])
        assert bytes(v1.encode()) == bytes(tlv_encode(v2))

    def test_parse_interop(self):
        """Wire produced by v1 can be parsed by v2 and vice-versa."""
        class V1(TlvModel):
            name  = NameField()
            count = UintField(0x0a)

        @dataclass
        class V2:
            name:  NDNName = field(default=None, metadata={'tlv_type': 0x07})
            count: int     = field(default=None, metadata={'tlv_type': 0x0a})

        v1 = V1(); v1.name = '/test'; v1.count = 7
        wire_from_v1 = bytes(v1.encode())

        p = tlv_parse(V2, wire_from_v1)
        assert Name.to_str(p.name) == '/test'
        assert p.count == 7

        v2 = V2(name='/test', count=7)
        wire_from_v2 = bytes(tlv_encode(v2))

        p2 = V1.parse(wire_from_v2)
        assert Name.to_str(p2.name) == '/test'
        assert p2.count == 7


# ---------------------------------------------------------------------------
# MapField tests
# ---------------------------------------------------------------------------

@dataclass
class _StrBytesMap:
    entries: Dict[str, bytes] = field(default_factory=dict, metadata={
        'tlv_type':     0x21,
        'val_tlv_type': 0x23,
    })


@dataclass
class _Inner2:
    value: int = field(default=None, metadata={'tlv_type': 0x01})


@dataclass
class _StrModelMap:
    entries: Dict[str, _Inner2] = field(default_factory=dict, metadata={
        'tlv_type':     0x21,
        'val_tlv_type': 0x22,
    })


class TestMapField:
    def test_str_bytes_roundtrip(self):
        obj = _StrBytesMap(entries={'alpha': b'\x01\x02', 'beta': b'\x03'})
        wire = tlv_encode(obj)
        p = tlv_parse(_StrBytesMap, wire)
        assert list(p.entries.keys()) == ['alpha', 'beta']
        assert bytes(p.entries['alpha']) == b'\x01\x02'
        assert bytes(p.entries['beta']) == b'\x03'

    def test_insertion_order_preserved(self):
        """Dict round-trip must preserve the original key insertion order."""
        obj = _StrBytesMap(entries={'z': b'\x00', 'a': b'\x01', 'm': b'\x02'})
        p = tlv_parse(_StrBytesMap, tlv_encode(obj))
        assert list(p.entries.keys()) == ['z', 'a', 'm']

    def test_empty_map_produces_no_bytes(self):
        obj = _StrBytesMap(entries={})
        assert tlv_encode(obj) == b''

    def test_none_map_produces_no_bytes(self):
        obj = _StrBytesMap(entries=None)
        assert tlv_encode(obj) == b''

    def test_none_map_defaults_to_empty_on_parse(self):
        """Parsing wire with no map TLVs leaves entries as the default_factory value."""
        p = tlv_parse(_StrBytesMap, b'')
        assert p.entries == {}

    def test_str_model_map_roundtrip(self):
        obj = _StrModelMap(entries={'x': _Inner2(value=7), 'y': _Inner2(value=99)})
        wire = tlv_encode(obj)
        p = tlv_parse(_StrModelMap, wire)
        assert list(p.entries.keys()) == ['x', 'y']
        assert p.entries['x'].value == 7
        assert p.entries['y'].value == 99

    def test_v1_compat_wire(self):
        """v2 map encoding must be byte-for-byte identical to v1 MapField."""
        from ndn.encoding import MapField, BytesField

        class V1Map(TlvModel):
            entries = MapField(BytesField(0x21, is_string=True), BytesField(0x23))

        v1 = V1Map()
        v1.entries['alpha'] = b'\x01\x02'
        v1.entries['beta']  = b'\x03'
        v1_wire = bytes(v1.encode())

        v2 = _StrBytesMap(entries={'alpha': b'\x01\x02', 'beta': b'\x03'})
        v2_wire = bytes(tlv_encode(v2))

        assert v1_wire == v2_wire

    def test_v1_produced_wire_parsed_by_v2(self):
        from ndn.encoding import MapField, BytesField

        class V1Map(TlvModel):
            entries = MapField(BytesField(0x21, is_string=True), BytesField(0x23))

        v1 = V1Map()
        v1.entries['hello'] = b'\xde\xad'
        wire = bytes(v1.encode())

        p = tlv_parse(_StrBytesMap, wire)
        assert bytes(p.entries['hello']) == b'\xde\xad'

    def test_bytes_values_are_memoryview_zero_copy(self):
        obj = _StrBytesMap(entries={'k': b'\xca\xfe'})
        wire = tlv_encode(obj)
        p = tlv_parse(_StrBytesMap, wire)
        assert isinstance(p.entries['k'], memoryview)
