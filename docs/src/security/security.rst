:mod:`ndn.security` package
============================

Introduction
------------

The :mod:`ndn.security` package provides signers, validators, keychains, and
TPM integrations.

Signer
------

A :class:`Signer` supplies signature metadata and computes a packet signature.

.. autoclass:: ndn.encoding.Signer
  :members:

Validator
---------

An application validator is an async callable with three arguments: a
:class:`FormalName`, :class:`SignaturePtrs`, and packet-context dictionary. It
returns :class:`ValidResult`. ``PASS`` and ``ALLOW_BYPASS`` accept a packet;
``FAIL`` and ``TIMEOUT`` reject it.

The digest and known-key validator factories exported from
:mod:`ndn.security` follow this contract.

Keychain
--------

A :class:`Keychain` contains identities, their keys, and certificates.

.. autoclass:: ndn.security.keychain.Keychain
  :members:

KeychainDigest
~~~~~~~~~~~~~~

.. automodule:: ndn.security.keychain.keychain_digest
  :members:

KeychainSqlite3
~~~~~~~~~~~~~~~

This is the default persistent keychain.

.. automodule:: ndn.security.keychain.keychain_sqlite3
  :members:
