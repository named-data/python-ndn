:mod:`ndn.app` package
======================

Introduction
------------

The :mod:`ndn.app` package contains :class:`NDNApp`, the canonical asyncio
application API. It connects to an NDN forwarder and provides:

* Interest expression and Data validation.
* Interest handlers with PIT-token-aware reply callbacks.
* Prefix registration and unregistration.
* Signed NFD management commands.

Consumer code calls :meth:`NDNApp.express` and receives ``(name, content,
context)``. The context contains parsed metadata, signature pointers, the raw
packet, and the deadline. Producer handlers receive ``(name, app_param, reply,
context)`` and should send encoded Data through ``reply`` so PIT tokens are
preserved.

The application does not own a keychain. Use :meth:`NDNApp.default_keychain`
when the default client configuration is desired, and pass an explicit signer
to :meth:`NDNApp.express` or :meth:`NDNApp.make_data`.

Reference
---------

.. automodule:: ndn.app
    :members:
