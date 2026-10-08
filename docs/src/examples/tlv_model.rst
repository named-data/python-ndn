Customized TLV Models
=====================

TLV models are Python dataclasses. Type annotations determine how values are
encoded, while ``dataclasses.field`` metadata supplies TLV type numbers and
special encoding options.

Encoding and parsing
--------------------

.. code-block:: python3

    from dataclasses import dataclass, field
    from ndn.encoding import NDNName, Name, tlv_encode, tlv_parse

    @dataclass
    class Model:
        name: NDNName = field(default=None, metadata={'tlv_type': 0x07})
        int_val: int = field(default=None, metadata={'tlv_type': 0x03})
        str_val: bytes = field(default=None, metadata={'tlv_type': 0x02})
        bool_val: bool = field(default=False, metadata={'tlv_type': 0x01})

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
        value: int = field(default=None, metadata={'tlv_type': 0x01})

    @dataclass
    class Outer:
        inner: Inner = field(default=None, metadata={'tlv_type': 0x02})
        words: list[int] = field(
            default_factory=list,
            metadata={'tlv_type': 0x03, 'fixed_len': 2},
        )
        labels: dict[str, bytes] = field(
            default_factory=dict,
            metadata={'tlv_type': 0x21, 'val_tlv_type': 0x23},
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

Metadata
--------

Common metadata keys are ``tlv_type``, ``fixed_len``, ``ignore_critical``,
``val_tlv_type``, and ``field_type``. ``field_type`` is reserved for special
fields such as offset markers, signature values, and Interest names used by
the packet-format implementation.
