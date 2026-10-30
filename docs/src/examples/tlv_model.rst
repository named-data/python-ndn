Customized TLV Models
=====================

TLV models are Python dataclasses. Type annotations determine how values are
encoded, while :func:`~ndn.encoding.tlv_field` supplies TLV type numbers and
special encoding options with type hints.

Encoding and parsing
--------------------

.. code-block:: python3

    from dataclasses import dataclass
    from ndn.encoding import NDNName, Name, tlv_encode, tlv_field, tlv_parse

    @dataclass
    class Model:
        name: NDNName | None = tlv_field(0x07, default=None)
        int_val: int | None = tlv_field(0x03, default=None)
        str_val: bytes | None = tlv_field(0x02, default=None)
        bool_val: bool = tlv_field(0x01, default=False)

    wire = tlv_encode(Model(name='/name', str_val=b'bit string'))
    parsed = tlv_parse(Model, wire)
    assert Name.to_str(parsed.name) == '/name'
    assert bytes(parsed.str_val) == b'bit string'

``None`` values are omitted. Boolean fields are encoded as zero-length TLVs
when true and are omitted when false.

Nested and repeated values
--------------------------

Dataclass annotations also describe nested models, repeated fields, and maps.

.. code-block:: python3

    @dataclass
    class Inner:
        value: int | None = tlv_field(0x01, default=None)

    @dataclass
    class Outer:
        inner: Inner | None = tlv_field(0x02, default=None)
        words: list[int] = tlv_field(
            0x03,
            default_factory=list,
            fixed_len=2,
        )
        labels: dict[str, bytes] = tlv_field(
            0x21,
            default_factory=dict,
            val_tlv_type=0x23,
        )

    wire = tlv_encode(Outer(
        inner=Inner(255),
        words=[0, 1, 2],
        labels={'key': b'value'},
    ))
    parsed = tlv_parse(Outer, wire)
    assert parsed.inner.value == 255

Dataclass inheritance places base-class fields before subclass fields. Unknown
critical TLVs raise :class:`DecodeError`; unknown non-critical TLVs are skipped.
The codec returns binary values as zero-copy ``memoryview`` slices where
possible.

Field options
-------------

The typed :func:`~ndn.encoding.tlv_field` arguments include ``tlv_type``,
``fixed_len``, ``ignore_critical``, ``val_tlv_type``, and ``field_type``.
``field_type`` is reserved for special fields such as offset markers,
signature values, and Interest names used by the packet-format implementation.
