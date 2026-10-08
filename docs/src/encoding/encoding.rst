:mod:`ndn.encoding` package
============================

Introduction
------------

The :mod:`ndn.encoding` package encodes and decodes TLV values, NDN names,
Interest packets, and Data packets. Its main parts are:

1. TLV number, Name, and NameComponent primitives.
2. Dataclass TLV models encoded with :func:`tlv_encode` and parsed with
   :func:`tlv_parse`.
3. NDN Packet Format 0.3 helpers for Interests and Data.

.. _label-different-names:

:any:`FormalName` and :any:`NonStrictName`
------------------------------------------

APIs accept :any:`NonStrictName` values in several forms but return the
canonical :any:`FormalName`, a list of encoded NameComponents.

.. code-block:: python3

    component = b'\x08\x09component'
    formal_name = [bytearray(b'\x08\x06formal'), b'\x08\x04name']
    casual_name_1 = '/non-strict/8=name'
    casual_name_2 = [bytearray(b'\x08\x0anon-strict'), 'name']
    casual_name_3 = b'\x07\x12\x08\x0anon-strict\x08\x04name'

Customized TLV Models
---------------------

See :doc:`../examples/tlv_model`.

Reference
---------

.. toctree::

    TLV Variables <tlv_var>
    Name and Component <name>
    Dataclass TLV Model <tlv_model>
    NDN Packet Format 0.3 <ndn_format_0_3>
