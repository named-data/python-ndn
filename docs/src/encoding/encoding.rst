:mod:`ndn.encoding` package
============================

Introduction
------------

The :mod:`ndn.encoding` package contains classes and functions
that help to encode and decode NDN Name, NameComponent, Data and Interest.

There are three parts of this package:

1. **TLV elements**: process TLV variables, Names and NameComponents.

2. **TlvModel**: design a general way to describe a TLV format object.
   A TLV format can be described with a class derived from ``TlvModel``,
   with members of type ``Field``.

3. **NDN Packet Fotmat v0.3**: functions used to encode and parse
   Interest and Data packets in
   `NDN Packet Format Spec 0.3 <http://named-data.net/doc/NDN-packet-spec/current/>`_.

FormalName and NonStrictName
----------------------------

Customized TLV Model
--------------------

Reference
---------

.. toctree::

    TLV Variables <tlv_var>
    Name and Component <name>
    TLV Model <tlv_model>
    NDN Packet Format 0.3 <ndn_format_0_3>
