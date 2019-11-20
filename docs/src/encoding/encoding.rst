:mod:`ndn.encoding` package
============================

Introduction
------------

The :mod:`ndn.encoding` package contains classes and functions
that help to encode and decode NDN Name, NameComponent, Data and Interest.

There are three parts of this package:

1. **TLV elements**: process TLV variables, Names and NameComponents.

2. **TlvModel**: design a general way to describe a TLV format.
   A TLV object can be described with a class derived from :any:`TlvModel`,
   with members of type :any:`Field`.

3. **NDN Packet Fotmat v0.3**: functions used to encode and parse
   Interest and Data packets in
   `NDN Packet Format Spec 0.3 <https://named-data.net/doc/NDN-packet-spec/current/>`_.

.. _label-different-names:

:any:`FormalName` and :any:`NonStrictName`
------------------------------------------

To increase the flexibility, API in ``python-ndn`` accepts Name arguments in a wide range of formats,
i.e. :any:`NonStrictName`, but returns an unified form, :any:`FormalName`.

A Component is a NameComponent encoded in TLV format.

.. code-block:: python3

    component = b'\x08\x09component'

A :any:`FormalName` is a list of encoded Components.

.. code-block:: python3

    formal_name = [bytearray(b'\x08\x06formal'), b'\x08\x04name']

A :any:`NonStrictName` is any of below:

- A URI string.

  .. code-block:: python3

      casual_name_1 = "/non-strict/8=name"

- A list or iterator of Components, in the form of either encoded TLV or URI string.

  .. code-block:: python3

      casual_name_2 = [bytearray(b'\x08\x0anon-strict'), 'name']
      casual_name_3 = (f'{x}' for x in range(3))

- An encoded Name of type :class:`bytes`, :class:`bytearray` or :class:`memoryview`.

  .. code-block:: python3

      casual_name_4 = b'\x07\x12\x08\x0anon-strict\x08\x04name'

Customized TLV Models
---------------------

See :doc:`../examples/tlv_model`

Reference
---------

.. toctree::

    TLV Variables <tlv_var>
    Name and Component <name>
    TLV Model <tlv_model>
    NDN Packet Format 0.3 <ndn_format_0_3>
