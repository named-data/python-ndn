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
| Dict[K, V]                                 | map      | MapField         |
+--------------------------------------------+----------+------------------+
| None  + field_type='offset_marker'         | (zero)   | OffsetMarker     |
+--------------------------------------------+----------+------------------+
| bytes + field_type='sig_value'             | (special)| SignatureValue   |
+--------------------------------------------+----------+------------------+
| NDNName + field_type='interest_name'       | (special)| InterestNameField|
+--------------------------------------------+----------+------------------+

Supported metadata keys
-----------------------
``'tlv_type'``       int   TLV type number (required except for offset_marker)
``'fixed_len'``      int   Force uint value width: 1, 2, 4, or 8 bytes
``'ignore_critical'  bool  Suppress DecodeError for nested model parsing
``'field_type'``     str   Explicit kind override when inference is insufficient

For **map** fields (``Dict[K, V]``):
``'val_tlv_type'``     int  TLV type for map values (required)

For **sig_value** fields:
``'cover_start'``      str  Name of the offset_marker field where sig coverage begins
``'digest_cover_start' str  Same or different offset_marker; where digest coverage begins
``'digest_cover_end'`` str  Offset_marker after sig_value; where digest coverage ends

Signature machinery markers (set by caller before tlv_encode / tlv_parse):
``markers['##signer']``        Signer instance; absent means unsigned
``markers['##need_digest']``   True ⟹ insert/compute ParametersSha256DigestComponent

Signature machinery markers (set by tlv_encode / tlv_parse internally):
``markers['##sig_covered_part']``   list[memoryview | bytes]: regions covered by sig
``markers['##sig_value_buf']``      writable memoryview into the placeholder bytes
``markers['##shrink_len']``         int: bytes trimmed from end after sig finalization
``markers['##digest_buf']``         writable memoryview into the digest component value
``markers[fname]``                  int: recorded byte offset for each offset_marker field
"""
import dataclasses
import struct
import typing
from enum import Enum, Flag
from hashlib import sha256

from .tlv_type import BinaryStr, VarBinaryStr, is_binary_str
from .tlv_var import write_tl_num, parse_tl_num, get_tl_num_size
from .name import Name, Component
from .tlv_model import DecodeError


__all__ = [
    'tlv_encode', 'tlv_parse', 'NDNName', 'DecodeError',
    'tlv_get_arg', 'tlv_set_arg',
]

# Kinds that occupy zero wire bytes and may not have a 'tlv_type' metadata key.
_ZERO_WIRE_KINDS = frozenset({'offset_marker'})


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
    if origin is dict:
        return 'map'
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


def _map_annotations(annotation):
    """Extract (K, V) from Dict[K, V]; falls back to (str, bytes)."""
    annotation = _unwrap_optional(annotation)
    args = typing.get_args(annotation)
    if len(args) == 2:
        return args[0], args[1]
    return str, bytes


def _map_key_meta(metadata: dict) -> dict:
    """Build a synthetic metadata dict for a map key sub-field."""
    return {'tlv_type': metadata['tlv_type']}


def _map_val_meta(metadata: dict) -> dict:
    """Build a synthetic metadata dict for a map value sub-field."""
    m = {'tlv_type': metadata['val_tlv_type']}
    if 'ignore_critical' in metadata:
        m['ignore_critical'] = metadata['ignore_critical']
    return m


# ---------------------------------------------------------------------------
# Interest-name helpers (used by both pass-1 and pass-2)
# ---------------------------------------------------------------------------

def _encoded_length_interest_name(fname: str, val, metadata: dict,
                                   markers: dict) -> int:
    """
    Size pass for an Interest Name field.

    Mirrors ``InterestNameField.encoded_length``.  If ``markers['##need_digest']``
    is truthy and the name does not already contain a
    ``ParametersSha256DigestComponent``, 34 extra bytes are reserved for one.
    """
    if val is None:
        return 0
    type_num = metadata['tlv_type']
    need_digest = markers.get('##need_digest', False)

    # Normalize to a list of component bytes.
    if isinstance(val, str):
        name = Name.from_str(val)
    elif is_binary_str(val):
        name = Name.decode(val)[0]
    else:
        name = list(val)
    for i, comp in enumerate(name):
        if isinstance(comp, str):
            name[i] = Component.from_str(Component.escape_str(comp))
        elif not is_binary_str(comp):
            raise TypeError(f'{fname}: invalid name component {comp!r}')

    # Locate an existing ParametersSha256DigestComponent (at most one allowed).
    digest_pos = None
    if need_digest:
        for i, comp in enumerate(name):
            if Component.get_type(comp) == Component.TYPE_PARAMETERS_SHA256:
                if digest_pos is None:
                    digest_pos = i
                else:
                    raise ValueError(
                        f'{fname}: multiple ParametersSha256DigestComponent in name')

    markers[f'{fname}##digest_pos'] = digest_pos
    markers[f'{fname}##preprocessed_name'] = name

    comp_total = sum(len(c) for c in name)
    if need_digest and digest_pos is None:
        # Reserve space for a new digest component: T(1B) + L(1B) + V(32B).
        comp_total += (get_tl_num_size(Component.TYPE_PARAMETERS_SHA256)
                       + get_tl_num_size(32) + 32)

    markers[f'{fname}##name_value_len'] = comp_total
    return get_tl_num_size(type_num) + get_tl_num_size(comp_total) + comp_total


def _encode_into_interest_name(fname: str, val, metadata: dict, markers: dict,
                                wire: VarBinaryStr, offset: int) -> int:
    """
    Write pass for an Interest Name field.

    Mirrors ``InterestNameField.encode_into``.  Appends non-digest name
    components to ``markers['##sig_covered_part']`` (wire slices) and stores
    the writable digest-value buffer in ``markers['##digest_buf']``.
    """
    if val is None:
        return 0
    type_num = metadata['tlv_type']
    name = markers[f'{fname}##preprocessed_name']
    comp_total = markers[f'{fname}##name_value_len']
    digest_pos = markers[f'{fname}##digest_pos']
    need_digest = markers.get('##need_digest', False)
    sig_covered_part = markers.setdefault('##sig_covered_part', [])

    origin = offset
    t_sz = write_tl_num(type_num, wire, offset);  offset += t_sz
    l_sz = write_tl_num(comp_total, wire, offset); offset += l_sz
    cover_start = offset

    for i, comp in enumerate(name):
        comp_len = len(comp)
        wire[offset:offset + comp_len] = comp
        if i == digest_pos:
            if offset > cover_start:
                sig_covered_part.append(wire[cover_start:offset])
            # Value of the digest component sits after T + L (each 1 byte for
            # TYPE_PARAMETERS_SHA256=2 < 253 and length=32 < 253).
            c_t_sz = get_tl_num_size(Component.TYPE_PARAMETERS_SHA256)
            c_l_sz = get_tl_num_size(32)
            markers['##digest_buf'] = wire[offset + c_t_sz + c_l_sz:offset + comp_len]
            cover_start = offset + comp_len
        offset += comp_len

    if offset > cover_start:
        sig_covered_part.append(wire[cover_start:offset])

    if need_digest and digest_pos is None:
        # Append a new ParametersSha256DigestComponent at the end of the name.
        c_t_sz = write_tl_num(Component.TYPE_PARAMETERS_SHA256, wire, offset)
        offset += c_t_sz
        c_l_sz = write_tl_num(32, wire, offset)
        offset += c_l_sz
        markers['##digest_buf'] = wire[offset:offset + 32]
        # Keep the preprocessed name up-to-date for get_final_name use.
        name.append(bytes(wire[offset - c_t_sz - c_l_sz:offset + 32]))
        offset += 32

    return offset - origin


# ---------------------------------------------------------------------------
# Post-encoding finalization (signature + SHA-256 digest)
# ---------------------------------------------------------------------------

def _finalize_encode(markers: dict, mv, model_end: int) -> int:
    """
    Called by :func:`tlv_encode` after all bytes have been written.

    1. Asks the signer to fill in the signature-value placeholder, updates the
       inline length byte if the actual signature is shorter (ECDSA), and
       records ``markers['##shrink_len']``.
    2. If ``markers['##need_digest']`` is set, computes ``SHA-256`` over the
       digest-covered range and writes it into the name's digest-component
       placeholder (``markers['##digest_buf']``).

    Returns *shrink_size* (0 for fixed-length signature schemes like HMAC/EdDSA).
    All offsets in *markers* are absolute positions within *mv*.
    """
    signer = markers.get('##signer')
    shrink_size = 0

    if signer is not None and '##sig_value_buf' in markers:
        sig_value_buf = markers['##sig_value_buf']
        alloc_size = len(sig_value_buf)
        real_size = signer.write_signature_value(
            sig_value_buf, markers.get('##sig_covered_part', []))
        shrink_size = alloc_size - real_size
        markers['##shrink_len'] = shrink_size
        if shrink_size > 0:
            if alloc_size >= 253:
                raise ValueError(
                    f'Signature with variable length ≥ 253 bytes is not supported '
                    f'(allocated {alloc_size})')
            markers['##sig_wire_l_field'][0] = real_size

    if markers.get('##need_digest') and '##digest_buf' in markers:
        d_start_field = markers.get('##_digest_cover_start_field')
        d_end_field   = markers.get('##_digest_cover_end_field')
        d_start = markers[d_start_field] if (d_start_field and d_start_field in markers) else 0
        d_end   = markers[d_end_field]   if (d_end_field   and d_end_field   in markers) else model_end
        d_end  -= shrink_size
        markers['##digest_buf'][:] = sha256(bytes(mv[d_start:d_end])).digest()

    return shrink_size


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
    # Zero-wire kinds: handled before looking up tlv_type.
    if kind == 'offset_marker':
        return 0

    if kind == 'sig_value':
        signer = markers.get('##signer')
        if signer is None:
            return 0
        type_num = metadata['tlv_type']
        sig_size = signer.get_signature_value_size()
        markers[f'{fname}##sig_size'] = sig_size
        markers.setdefault('##sig_covered_part', [])
        return get_tl_num_size(type_num) + get_tl_num_size(sig_size) + sig_size

    if kind == 'interest_name':
        return _encoded_length_interest_name(fname, val, metadata, markers)

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

    if kind == 'map':
        if not val:
            return 0
        key_ann, val_ann = _map_annotations(annotation)
        key_meta = _map_key_meta(metadata)
        vl_meta  = _map_val_meta(metadata)
        key_kind = _infer_kind(key_ann, key_meta)
        vl_kind  = _infer_kind(val_ann, vl_meta)
        total = 0
        for i, (k, v) in enumerate(val.items()):
            total += _encoded_length_field(
                f'{fname}[{i}#k]', k, key_kind, key_ann, key_meta, markers)
            total += _encoded_length_field(
                f'{fname}[{i}#v]', v, vl_kind,  val_ann, vl_meta,  markers)
        return total

    raise TypeError(f'Unknown field kind {kind!r} for {fname!r}')


def _encoded_length_model(obj, markers: dict) -> int:
    """Compute the total encoded length for all TLV fields of a dataclass object."""
    cls = type(obj)
    hints = typing.get_type_hints(cls)
    total = 0
    for f in dataclasses.fields(cls):
        ann = hints[f.name]
        kind = _infer_kind(ann, f.metadata)
        if kind not in _ZERO_WIRE_KINDS and 'tlv_type' not in f.metadata:
            continue
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
    # Zero-wire kinds: handled before looking up tlv_type.
    if kind == 'offset_marker':
        markers[fname] = offset
        return 0

    if kind == 'sig_value':
        signer = markers.get('##signer')
        if signer is None:
            return 0
        type_num = metadata['tlv_type']
        sig_size = markers[f'{fname}##sig_size']
        # Collect the covered region: from cover_start up to current offset.
        cover_start_field = metadata.get('cover_start')
        cover_start = markers.get(cover_start_field, 0) if cover_start_field else 0
        markers.setdefault('##sig_covered_part', []).append(wire[cover_start:offset])
        # Store digest-coverage field names for _finalize_encode.
        for mkey in ('digest_cover_start', 'digest_cover_end'):
            if mkey in metadata:
                markers[f'##_{mkey}_field'] = metadata[mkey]
        # Write T + L (stored for in-place shrink) + placeholder V.
        t_sz = write_tl_num(type_num, wire, offset)
        l_off = offset + t_sz
        l_sz = write_tl_num(sig_size, wire, l_off)
        markers['##sig_wire_l_field'] = wire[l_off:l_off + l_sz]
        v_start = l_off + l_sz
        markers['##sig_value_buf'] = wire[v_start:v_start + sig_size]
        return t_sz + l_sz + sig_size

    if kind == 'interest_name':
        return _encode_into_interest_name(fname, val, metadata, markers, wire, offset)

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

    if kind == 'map':
        if not val:
            return 0
        key_ann, val_ann = _map_annotations(annotation)
        key_meta = _map_key_meta(metadata)
        vl_meta  = _map_val_meta(metadata)
        key_kind = _infer_kind(key_ann, key_meta)
        vl_kind  = _infer_kind(val_ann, vl_meta)
        total = 0
        for i, (k, v) in enumerate(val.items()):
            total += _encode_into_field(
                f'{fname}[{i}#k]', k, key_kind, key_ann, key_meta, markers,
                wire, offset + total)
            total += _encode_into_field(
                f'{fname}[{i}#v]', v, vl_kind,  val_ann, vl_meta,  markers,
                wire, offset + total)
        return total

    raise TypeError(f'Unknown field kind {kind!r} for {fname!r}')


def _encode_into_model(obj, markers: dict, wire: VarBinaryStr, offset: int) -> None:
    """Write all TLV fields of a dataclass object into *wire* starting at *offset*."""
    cls = type(obj)
    hints = typing.get_type_hints(cls)
    for f in dataclasses.fields(cls):
        ann = hints[f.name]
        kind = _infer_kind(ann, f.metadata)
        if kind not in _ZERO_WIRE_KINDS and 'tlv_type' not in f.metadata:
            continue
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
        mv = memoryview(buf)
        _encode_into_model(obj, markers, mv, 0)
        shrink = _finalize_encode(markers, mv, total)
        if shrink:
            # Can't resize bytearray while memoryview exports are live (the sig/digest
            # slices in markers still reference mv).  Return a trimmed copy instead.
            return bytearray(mv[:total - shrink])
        return buf
    mv = memoryview(wire)
    _encode_into_model(obj, markers, mv, offset)
    shrink = _finalize_encode(markers, mv, offset + total)
    return mv[offset:offset + total - shrink]


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


def tlv_parse(cls, wire, ignore_critical: bool = False, markers: dict = None):
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
    :param markers: optional dict for out-of-band state (offset_marker positions,
                    sig/digest buffers).  A fresh ``{}`` is used when ``None``.
    :return: populated dataclass instance.
    :raises DecodeError: unknown critical TLV type encountered.
    """
    if markers is None:
        markers = {}

    # Wrap in memoryview for zero-copy slicing throughout the parse
    if isinstance(wire, memoryview):
        mv = wire
    else:
        mv = memoryview(wire if isinstance(wire, (bytes, bytearray)) else bytes(wire))

    hints = typing.get_type_hints(cls)
    ordered = []
    for f in dataclasses.fields(cls):
        ann = hints[f.name]
        kind = _infer_kind(ann, f.metadata)
        if kind not in _ZERO_WIRE_KINDS and 'tlv_type' not in f.metadata:
            continue
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
            if kind == 'offset_marker':
                continue                        # never matches a wire TLV type

            if meta['tlv_type'] != typ:
                continue

            # Advance any offset_markers between field_pos and i.
            for j in range(field_pos, i):
                jname, _, jkind, _ = ordered[j]
                if jkind == 'offset_marker':
                    markers[jname] = offset_btl

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

            elif kind == 'map':
                # Two-phase parse: consume key, then immediately read value TLV.
                key_ann, val_ann = _map_annotations(ann)
                key_meta = _map_key_meta(meta)
                vl_meta  = _map_val_meta(meta)
                key_kind = _infer_kind(key_ann, key_meta)
                vl_kind  = _infer_kind(val_ann, vl_meta)

                dct = getattr(obj, fname)
                if dct is None:
                    dct = {}
                    object.__setattr__(obj, fname, dct)
                idx = len(dct)

                key = _parse_value(f'{fname}[{idx}#k]', key_kind, key_ann, key_meta,
                                   mv, offset, length, offset_btl, ignore_critical)

                # advance past key value → now at the value TLV
                offset += length
                offset_btl = offset
                _val_typ, _sz_t2 = parse_tl_num(mv, offset)
                offset += _sz_t2
                length, _sz_l2 = parse_tl_num(mv, offset)
                offset += _sz_l2

                val = _parse_value(f'{fname}[{idx}#v]', vl_kind, val_ann, vl_meta,
                                   mv, offset, length, offset_btl, ignore_critical)
                dct[key] = val
                field_pos = i                   # stay at i to accept more pairs

            elif kind == 'sig_value':
                # Extract sig buffer; append covered region to ##sig_covered_part.
                sig_buf = mv[offset:offset + length]
                markers['##sig_value_buf'] = sig_buf
                cover_start_field = meta.get('cover_start')
                if cover_start_field is not None:
                    cover_start = markers.get(cover_start_field)
                    if cover_start is not None:
                        markers.setdefault('##sig_covered_part', []).append(
                            mv[cover_start:offset_btl])
                object.__setattr__(obj, fname, sig_buf)
                field_pos = i + 1

            elif kind == 'interest_name':
                # Decode name; split into sig-covered components and digest buf.
                name = Name.decode(mv, offset_btl)[0]
                sig_cp = markers.setdefault('##sig_covered_part', [])
                for comp in name:
                    if Component.get_type(comp) == Component.TYPE_PARAMETERS_SHA256:
                        markers['##digest_buf'] = Component.get_value(comp)
                    else:
                        sig_cp.append(comp)
                object.__setattr__(obj, fname, name)
                field_pos = i + 1

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


# ---------------------------------------------------------------------------
# Marker helpers (convenience wrappers for the markers dict)
# ---------------------------------------------------------------------------

def tlv_get_arg(markers: dict, key: str, default=None):
    """
    Read a value from the *markers* dict used by :func:`tlv_encode` /
    :func:`tlv_parse`.

    Equivalent to ``markers.get(key, default)``.
    """
    return markers.get(key, default)


def tlv_set_arg(markers: dict, key: str, val) -> None:
    """
    Write a value into the *markers* dict used by :func:`tlv_encode` /
    :func:`tlv_parse`.

    Equivalent to ``markers[key] = val``.
    """
    markers[key] = val
