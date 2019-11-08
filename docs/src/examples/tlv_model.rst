Customized TLV Models
=====================

Encoding
--------

``python-ndn`` provides a descriptive way to define a specific TLV format, called TLV model.
Every object can be described by a class derived from :any:`TlvModel`.
Elements of a TLV object is expressed as an instance variable of :any:`Field`.
Fields are encoded in order.

.. code-block:: python3

    from ndn.encoding import *

    class Model(TlvModel):          # Model = [Name] [IntVal] [StrVal] [BoolVal]
        name = NameField()          # Name = NAME-TYPE TLV-LENGTH ...
        int_val = UintField(0x03)   # IntVal = INT-VAL-TYPE TLV-LENGTH nonNegativeInteger
        str_val = BytesField(0x02)  # StrVal = STR-VAL-TYPE TLV-LENGTH *OCTET
        bool_val = BoolField(0x01)  # BoolVal = BOOL-VAL-TYPE 0

    model = Model()
    model.name = '/name'
    model.str_val = b'bit string'
    assert model.encode() == b'\x07\x06\x08\x04name\x02\nbit string'

    model = Model.parse(b'\x07\x06\x08\x04name\x02\nbit string')
    assert model.str_val == b'bit string'

There is *no required* fields in a TLV model.
Every :any:`Field` is ``None`` by default, which means it will not be encoded.

Nested Model
------------

``python-ndn`` allows a TLV model to be a field (:any:`ModelField`) of another TLV model,
which enables a hierarchical structure.
Also, a TLV model does not contain the outer Type and Length.
This can be solved by encapsulating it into another TLV model.

.. code-block:: python3

    class Inner(TlvModel):              # Inner = [Val1]
        val1 = UintField(0x01)          # Val1  = 1 TLV-LENGTH nonNegativeInteger

    class Outer(TlvModel):              # Outer = [Val2]
        val2 = ModelField(0x02, Inner)  # Val2  = 2 TLV-LENGTH Inner

    obj = Outer()
    obj.val2 = Inner()
    obj.val2.val1 = 255
    assert obj.encode() == b'\x02\x03\x01\x01\xFF'

Repeated Model
--------------

:any:`RepeatedField` is an array of a specific type of field.
When encoding, elements are encoded in order.

.. code-block:: python3

    class WordArray(TlvModel):                               # WordArray = *Words
        words = RepeatedField(UintField(0x01, fixed_len=2))  # Words = 1 2 2OCTET

    array = WordArray()
    array.words = [i for i in range(3)]
    assert array.encode() == b'\x01\x02\x00\x00\x01\x02\x00\x01\x01\x02\x00\x02'

Derivation
----------

To avoid duplication, a :any:`TlvModel` can extend 1 or more other TlvModels.
However, to indicate the locations of base classes in the TLV encoded wire,
there must be an field for every base class to explicitly include its base class.
These fields must have the value :any:`IncludeBase`.
TlvModel instances' Include fields cannot be assigned, and will be ignored during encoding and parsing.

.. code-block:: python3

    class Base(TlvModel):         # Base = [M2]
        m2 = UintField(0x02)

    class Derived(Base):          # Derived = [M1] [M2] [M3]
        m1 = UintField(0x01)
        _base = IncludeBase(Base)
        m3 = UintField(0x03)

    obj = Derived()
    obj.m1, obj.m2, obj.m3 = range(1, 4)
    assert obj.encode() == b'\x01\x01\x01\x02\x01\x02\x03\x01\x03'

Overriding
----------

The derived class can override fields of its base classes.
To override a field, declare a field with the same name *after* the including.
Overriding fields will be encoded in their *original* places, irrelevant to the order of declaration.

.. code-block:: python3

    class A1(TlvModel):          # A1 = [M1]
        m1 = UintField(0x01)

    class A2(A1):                # A2 = [M1] [M2]
        _a1 = IncludeBase(A1)
        m2 = UintField(0x02)

    class B1(TlvModel):          # B1 = [X] [A1] [Y]
        x = UintField(0x0a)
        a = ModelField(0x03, A1)
        y = UintField(0x0b)

    class B2(B1):                # B2 = [X] [A2] [Y]
        IncludeBase(B1)
        a = ModelField(0x03, A2)

Parsing
-------

TODO:

- Fields are parsed in order.
- Out of order / Unknown fields are decided by critical.
- Signature.
