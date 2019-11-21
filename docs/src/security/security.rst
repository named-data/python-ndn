:mod:`ndn.security` package
============================

Introduction
------------

The :mod:`ndn.security` package provides basic tools for security use.

Signer
------

A :any:`Signer` is a class used to sign a packet during encoding.

.. autoclass:: ndn.encoding.Signer
  :members:

Validator
---------

A :any:`Validator` is a async function called to validate an Interest or Data packet.
It takes 2 arguments: a :any:`FormalName` and a :any:`SignaturePtrs`,
and returns whether the packet is validated.

Keychain
--------

A :any:`Keychain` is a class which contains Identities, Keys associated with Identities and associated Certificates.

.. autoclass:: ndn.security.keychain.Keychain
  :members:


KeychainDigest
~~~~~~~~~~~~~~
.. automodule:: ndn.security.keychain.keychain_digest
  :members:


KeychainSqlite3
~~~~~~~~~~~~~~~

This is the default Keychain.

.. automodule:: ndn.security.keychain.keychain_sqlite3
  :members:
