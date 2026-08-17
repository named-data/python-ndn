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
Dataclass-based TLV encoding/decoding (v2 API).

Usage::

    from dataclasses import dataclass, field
    from typing import List, Optional
    from ndn.encoding import tlv_encode, tlv_parse, NDNName

    @dataclass
    class Inner:
        value: int = field(default=None, metadata={'tlv_type': 0x01})

    @dataclass
    class Outer:
        name:    NDNName     = field(default=None, metadata={'tlv_type': 0x07})
        count:   int         = field(default=None, metadata={'tlv_type': 0x0a})
        payload: bytes       = field(default=None, metadata={'tlv_type': 0x15})
        sub:     Inner       = field(default=None, metadata={'tlv_type': 0x16})
        tags:    List[bytes] = field(default_factory=list,
                                     metadata={'tlv_type': 0x17})

    wire = tlv_encode(obj)
    obj  = tlv_parse(Outer, wire)

Field-kind inference from Python annotation
-------------------------------------------
+--------------------------------------------+----------+------------------+
| Annotation                                 | Kind     | Old equivalent   |
+============================================+==========+==================+
| int / Enum / Flag subclass                 | uint     | UintField        |
+--------------------------------------------+----------+------------------+
| bool                                       | bool     | BoolField        |
+--------------------------------------------+----------+------------------+
| bytes / bytearray / memoryview             | bytes    | BytesField       |
+--------------------------------------------+----------+------------------+
| str                                        | str      | BytesField       |
|                                            |          | (is_string=True) |
+--------------------------------------------+----------+------------------+
| NDNName (sentinel)                         | name     | NameField        |
+--------------------------------------------+----------+------------------+
| Any @dataclass type                        | model    | ModelField       |
+--------------------------------------------+----------+------------------+
| List[T]                                    | repeated | RepeatedField    |
+--------------------------------------------+----------+------------------+

Supported metadata keys
-----------------------
``'tlv_type'``      int   TLV type number (required for every TLV field)
``'fixed_len'``     int   Force uint value width: 1, 2, 4, or 8 bytes
``'ignore_critical' bool  Suppress DecodeError for nested model parsing
``'field_type'``    str   Explicit kind override when inference is insufficient
"""
import dataclasses
import struct
import typing
from enum import Enum, Flag

from .tlv_type import BinaryStr, VarBinaryStr, is_binary_str
from .tlv_var import write_tl_num, parse_tl_num, get_tl_num_size
from .name import Name, Component
from .tlv_model import DecodeError


__all__ = ['tlv_encode', 'tlv_parse', 'NDNName', 'DecodeError']


# ---------------------------------------------------------------------------
# NDNName sentinel — used as a type annotation for NDN Name fields
# ---------------------------------------------------------------------------

class NDNName:
    """
    Sentinel annotation type that marks a field as an NDN Name.

    Use it wherever you would have used :class:`~ndn.encoding.NameField` in
    the old metaclass API::

        name: NDNName = field(default=None, metadata={'tlv_type': 0x07})
        # repeated Names:
        names: List[NDNName] = field(default_factory=list,
                                     metadata={'tlv_type': 0x07})

    The actual runtime value is :any:`FormalName` (a list of encoded
    component bytes), exactly as returned by the old NameField.
    """


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------

def _unwrap_optional(annotation):
    """Return T for Optional[T] = Union[T, None]; otherwise return unchanged."""
    if typing.get_origin(annotation) is typing.Union:
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _infer_kind(annotation, metadata: dict) -> str:
    """
    Determine the TLV field kind from a Python type annotation plus metadata.

    Returns one of: ``'uint'``, ``'bool'``, ``'bytes'``, ``'str'``,
    ``'name'``, ``'model'``, ``'repeated'``.

    The ``'field_type'`` metadata key overrides automatic inference.
    """
    if 'field_type' in metadata:
        return metadata['field_type']

    annotation = _unwrap_optional(annotation)
    origin = typing.get_origin(annotation)

    if origin is list:
        return 'repeated'
    if annotation is NDNName:
        return 'name'
    # bool must be checked before int since bool is a subclass of int
    if annotation is bool:
        return 'bool'
    if annotation is int or (
            isinstance(annotation, type)
            and issubclass(annotation, (int, Enum, Flag))
            and annotation is not bool):
        return 'uint'
    if annotation in (bytes, bytearray, memoryview):
        return 'bytes'
    if annotation is str:
        return 'str'
    if dataclasses.is_dataclass(annotation):
        return 'model'

    raise TypeError(
        f'Cannot infer TLV field kind from annotation {annotation!r}. '
        f"Use metadata key 'field_type' to override."
    )


def _element_annotation(annotation):
    """Extract T from List[T]; falls back to bytes."""
    annotation = _unwrap_optional(annotation)
    args = typing.get_args(annotation)
    return args[0] if args else bytes


# ---------------------------------------------------------------------------
# Encoding — pass 1: size computation
# ---------------------------------------------------------------------------

def _uint_value_len(val: int, fname: str, fixed_len) -> int:
    if fixed_len is not None:
        n = fixed_len
    elif val <= 0xFF:
        n = 1
    elif val <= 0xFFFF:
        n = 2
    elif val <= 0xFFFFFFFF:
        n = 4
    else:
        n = 8
    if val >= 0x100 ** n:
        raise ValueError(f'{fname}={val!r} cannot be encoded into {n} bytes')
    return n


def _encoded_length_field(fname: str, val, kind: str, annotation, metadata: dict,
                           markers: dict) -> int:
    """
    Compute the encoded byte count of one TLV field (T + L + V).

    Intermediate values are cached in *markers* under ``fname##...`` keys,
    exactly mirroring the convention used by the v1 :class:`~ndn.encoding.Field`
    subclasses.  Returns 0 when the field is absent (*val* is ``None``/falsy
    for bool).
    """
    type_num = metadata['tlv_type']

    # BoolField: present if truthy, absent otherwise
    if kind == 'bool':
        return (get_tl_num_size(type_num) + 1) if val else 0

    if val is None:
        return 0

    if kind == 'uint':
        if isinstance(val, (Enum, Flag)):
            val = val.value
        if not isinstance(val, int) or val < 0:
            raise TypeError(f'{fname}={val!r} is not a non-negative integer')
        fixed_len = metadata.get('fixed_len')
        vlen = _uint_value_len(val, fname, fixed_len)
        markers[f'{fname}##encoded_length'] = vlen
        # L for uint is always 1 byte because vlen ∈ {1,2,4,8} < 253
        return get_tl_num_size(type_num) + 1 + vlen

    if kind in ('bytes', 'str'):
        if isinstance(val, str):
            raw = val.encode('utf-8')
            markers[f'{fname}##encoded_str'] = raw
        else:
            raw = val
        n = len(raw)
        return get_tl_num_size(type_num) + get_tl_num_size(n) + n

    if kind == 'name':
        # Normalise to list-of-components or a pre-encoded binary blob
        name_val = val
        if isinstance(name_val, str):
            name_val = Name.from_str(name_val)
        elif not is_binary_str(name_val):
            if hasattr(name_val, '__iter__'):
                name_val = list(name_val)
                for i, comp in enumerate(name_val):
                    if isinstance(comp, str):
                        name_val[i] = Component.from_str(Component.escape_str(comp))
                    elif not is_binary_str(comp):
                        raise TypeError(f'{fname}: invalid name component type')
            else:
                raise TypeError(f'{fname}: invalid name type')
        if isinstance(name_val, list):
            total_with_tl = Name.encoded_length(name_val)
        else:
            total_with_tl = len(name_val)
        markers[f'{fname}##preprocessed_name'] = name_val
        markers[f'{fname}##encoded_length_with_tl'] = total_with_tl
        return total_with_tl

    if kind == 'model':
        inner_markers: dict = {}
        length = _encoded_length_model(val, inner_markers)
        markers[f'{fname}##inner_markers'] = inner_markers
        markers[f'{fname}##encoded_length'] = length
        return get_tl_num_size(type_num) + get_tl_num_size(length) + length

    if kind == 'repeated':
        if not val:
            return 0
        elem_ann = _element_annotation(annotation)
        elem_kind = _infer_kind(elem_ann, metadata)
        total = 0
        for i, ele in enumerate(val):
            total += _encoded_length_field(
                f'{fname}[{i}]', ele, elem_kind, elem_ann, metadata, markers)
        return total

    raise TypeError(f'Unknown field kind {kind!r} for {fname!r}')


def _encoded_length_model(obj, markers: dict) -> int:
    """Compute the total encoded length for all TLV fields of a dataclass object."""
    cls = type(obj)
    hints = typing.get_type_hints(cls)
    total = 0
    for f in dataclasses.fields(cls):
        if 'tlv_type' not in f.metadata:
            continue
        ann = hints[f.name]
        kind = _infer_kind(ann, f.metadata)
        total += _encoded_length_field(
            f.name, getattr(obj, f.name), kind, ann, f.metadata, markers)
    markers['##encoded_length'] = total
    return total


# ---------------------------------------------------------------------------
# Encoding — pass 2: write bytes
# ---------------------------------------------------------------------------

def _encode_into_field(fname: str, val, kind: str, annotation, metadata: dict,
                       markers: dict, wire: VarBinaryStr, offset: int) -> int:
    """
    Write one TLV field into *wire* at *offset*.

    *wire* must be a writable :class:`memoryview` (or :class:`bytearray`).
    Returns the number of bytes written.  Must be called after the matching
    :func:`_encoded_length_field` call so that ``markers`` is populated.
    """
    type_num = metadata['tlv_type']

    if kind == 'bool':
        if val:
            t_size = write_tl_num(type_num, wire, offset)
            wire[offset + t_size] = 0           # L = 0
            return t_size + 1
        return 0

    if val is None:
        return 0

    if kind == 'uint':
        if isinstance(val, (Enum, Flag)):
            val = val.value
        vlen = markers[f'{fname}##encoded_length']
        t_size = write_tl_num(type_num, wire, offset)
        if vlen == 1:
            struct.pack_into('!BB', wire, offset + t_size, 1, val)
        elif vlen == 2:
            struct.pack_into('!BH', wire, offset + t_size, 2, val)
        elif vlen == 4:
            struct.pack_into('!BI', wire, offset + t_size, 4, val)
        else:
            struct.pack_into('!BQ', wire, offset + t_size, 8, val)
        return t_size + 1 + vlen               # T + L(1 byte) + V

    if kind in ('bytes', 'str'):
        raw = markers.get(f'{fname}##encoded_str')
        if raw is None:
            raw = val.encode('utf-8') if isinstance(val, str) else val
        n = len(raw)
        t_size = write_tl_num(type_num, wire, offset)
        l_size = write_tl_num(n, wire, offset + t_size)
        v_start = offset + t_size + l_size
        wire[v_start:v_start + n] = raw        # zero-copy slice assignment
        return t_size + l_size + n

    if kind == 'name':
        name_val = markers[f'{fname}##preprocessed_name']
        name_len = markers[f'{fname}##encoded_length_with_tl']
        if isinstance(name_val, list):
            Name.encode(name_val, wire, offset)
        else:
            wire[offset:offset + name_len] = name_val
        return name_len

    if kind == 'model':
        inner_markers = markers[f'{fname}##inner_markers']
        length = markers[f'{fname}##encoded_length']
        t_size = write_tl_num(type_num, wire, offset)
        l_size = write_tl_num(length, wire, offset + t_size)
        _encode_into_model(val, inner_markers, wire, offset + t_size + l_size)
        return t_size + l_size + length

    if kind == 'repeated':
        if not val:
            return 0
        elem_ann = _element_annotation(annotation)
        elem_kind = _infer_kind(elem_ann, metadata)
        total = 0
        for i, ele in enumerate(val):
            total += _encode_into_field(
                f'{fname}[{i}]', ele, elem_kind, elem_ann, metadata, markers,
                wire, offset + total)
        return total

    raise TypeError(f'Unknown field kind {kind!r} for {fname!r}')


def _encode_into_model(obj, markers: dict, wire: VarBinaryStr, offset: int) -> None:
    """Write all TLV fields of a dataclass object into *wire* starting at *offset*."""
    cls = type(obj)
    hints = typing.get_type_hints(cls)
    for f in dataclasses.fields(cls):
        if 'tlv_type' not in f.metadata:
            continue
        ann = hints[f.name]
        kind = _infer_kind(ann, f.metadata)
        offset += _encode_into_field(
            f.name, getattr(obj, f.name), kind, ann, f.metadata, markers, wire, offset)


# ---------------------------------------------------------------------------
# Public encode entry point
# ---------------------------------------------------------------------------

def tlv_encode(obj, wire=None, offset: int = 0, markers: dict = None):
    """
    Encode a dataclass TLV object.

    **Allocating form** — ``tlv_encode(obj)``
        Allocates a new :class:`bytearray`, fills it, and returns it.

    **In-place form** — ``tlv_encode(obj, wire, offset=0)``
        Encodes into an existing *wire* (:class:`bytearray` or writable
        :class:`memoryview`) starting at *offset*.  Returns a zero-copy
        :class:`memoryview` slice of the written region.

    :param obj: dataclass instance to encode.
    :param wire: optional writable buffer.
    :param offset: starting byte offset within *wire*.
    :param markers: optional shared markers dict (for multi-model coordination).
    :return: :class:`bytearray` (allocating) or :class:`memoryview` (in-place).
    """
    if markers is None:
        markers = {}
    total = _encoded_length_model(obj, markers)
    if wire is None:
        buf = bytearray(total)
        _encode_into_model(obj, markers, memoryview(buf), 0)
        return buf
    mv = memoryview(wire)
    _encode_into_model(obj, markers, mv, offset)
    return mv[offset:offset + total]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _make_default_instance(cls):
    """
    Create a dataclass instance with all fields set to their defaults.

    Uses ``object.__new__`` to bypass ``__init__``, then sets each field:
    - ``field(default=X)``          → X
    - ``field(default_factory=F)``  → F()
    - no default                    → None  (same behaviour as old TlvModel.parse)
    """
    obj = object.__new__(cls)
    for f in dataclasses.fields(cls):
        if f.default is not dataclasses.MISSING:
            object.__setattr__(obj, f.name, f.default)
        elif f.default_factory is not dataclasses.MISSING:
            object.__setattr__(obj, f.name, f.default_factory())
        else:
            object.__setattr__(obj, f.name, None)
    return obj


def _parse_value(fname: str, kind: str, annotation, metadata: dict,
                 wire, offset: int, length: int, offset_btl: int,
                 ignore_critical: bool):
    """
    Parse a single TLV *value* (V only, not T or L) from *wire*.

    :param fname: field name (for error messages).
    :param kind: field kind string.
    :param annotation: resolved Python type annotation.
    :param metadata: dataclass field metadata dict.
    :param wire: memoryview of the full wire buffer.
    :param offset: byte offset of V within *wire*.
    :param length: byte length of V.
    :param offset_btl: byte offset of the TLV's T field within *wire*
                       (used by NameField to pass to ``Name.decode``).
    :param ignore_critical: forwarded to nested ``tlv_parse`` calls.
    :return: the parsed Python value.
    """
    if kind == 'bool':
        return True

    if kind == 'uint':
        if length == 1:
            raw = struct.unpack_from('!B', wire, offset)[0]
        elif length == 2:
            raw = struct.unpack_from('!H', wire, offset)[0]
        elif length == 4:
            raw = struct.unpack_from('!I', wire, offset)[0]
        elif length == 8:
            raw = struct.unpack_from('!Q', wire, offset)[0]
        else:
            raise ValueError(
                f'{fname}: uint value length must be 1, 2, 4, or 8; got {length}')
        # Auto-convert to the annotated Enum/Flag type if applicable
        inner = _unwrap_optional(annotation)
        if (isinstance(inner, type)
                and issubclass(inner, (Enum, Flag))
                and inner is not int):
            try:
                return inner(raw)
            except ValueError:
                pass
        return raw

    if kind == 'bytes':
        return wire[offset:offset + length]     # zero-copy memoryview slice

    if kind == 'str':
        return bytes(wire[offset:offset + length]).decode('utf-8')

    if kind == 'name':
        return Name.decode(wire, offset_btl)[0]

    if kind == 'model':
        inner_cls = _unwrap_optional(annotation)
        ignore = metadata.get('ignore_critical', ignore_critical)
        return tlv_parse(inner_cls, wire[offset:offset + length], ignore)

    raise TypeError(f'Unknown kind {kind!r} for {fname!r}')


def tlv_parse(cls, wire, ignore_critical: bool = False):
    """
    Parse a TLV-encoded buffer into a fresh dataclass instance.

    Matching follows NDN ordering rules — fields are matched in their
    declaration order within *cls* (parent class fields come first, as per
    standard Python dataclass inheritance).

    Unknown critical TLV types (odd type numbers) raise
    :exc:`~ndn.encoding.DecodeError` unless *ignore_critical* is ``True``.

    Bytes-typed fields (``bytes``, ``bytearray``, ``memoryview`` annotations)
    are returned as zero-copy :class:`memoryview` slices into *wire*.

    :param cls: dataclass class to parse into.
    :param wire: TLV-encoded buffer
                 (:class:`bytes`, :class:`bytearray`, or :class:`memoryview`).
    :param ignore_critical: suppress :exc:`DecodeError` for unknown critical
                            TLV types.
    :return: populated dataclass instance.
    :raises DecodeError: unknown critical TLV type encountered.
    """
    # Wrap in memoryview for zero-copy slicing throughout the parse
    if isinstance(wire, memoryview):
        mv = wire
    else:
        mv = memoryview(wire if isinstance(wire, (bytes, bytearray)) else bytes(wire))

    hints = typing.get_type_hints(cls)
    ordered = []
    for f in dataclasses.fields(cls):
        if 'tlv_type' not in f.metadata:
            continue
        ann = hints[f.name]
        kind = _infer_kind(ann, f.metadata)
        ordered.append((f.name, f.metadata, kind, ann))

    obj = _make_default_instance(cls)
    offset = 0
    field_pos = 0                               # lowest index still eligible for matching

    while offset < len(mv):
        offset_btl = offset
        typ, sz_t = parse_tl_num(mv, offset)
        offset += sz_t
        length, sz_l = parse_tl_num(mv, offset)
        offset += sz_l

        found = False
        for i in range(field_pos, len(ordered)):
            fname, meta, kind, ann = ordered[i]
            if meta['tlv_type'] != typ:
                continue

            if kind == 'repeated':
                elem_ann = _element_annotation(ann)
                elem_kind = _infer_kind(elem_ann, meta)
                val = _parse_value(fname, elem_kind, elem_ann, meta,
                                   mv, offset, length, offset_btl, ignore_critical)
                lst = getattr(obj, fname)
                if lst is None:
                    lst = []
                    object.__setattr__(obj, fname, lst)
                lst.append(val)
                field_pos = i                   # stay at i to accept more elements
            else:
                val = _parse_value(fname, kind, ann, meta,
                                   mv, offset, length, offset_btl, ignore_critical)
                object.__setattr__(obj, fname, val)
                field_pos = i + 1

            found = True
            break

        if not found and (typ & 1) and not ignore_critical:
            raise DecodeError(
                f'unknown critical TLV type {typ:#x} is unrecognized, '
                f'redundant, or out-of-order')

        offset += length

    return obj
