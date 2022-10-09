:mod:`ndn.appv2` package
========================

Introduction
------------

The :mod:`ndn.appv2` package contains ``NDNApp`` class.
It offers the functionalities similar to an application face in other NDN libraries.
Main features include:

+ Establish a connection to NDN forwarder.
+ Consumer: express Interests and receive the reply Data.
+ Producer: attach Interest handler function to a name prefix, to handle incoming Interests.
+ Producer: register and unregister prefixes in the forwarder.

This package is a rewrite from :mod:`ndn.app` package.
Major differences from that package are:

+ Initial support for PIT token.
+ Send signed Interests for NFD management commands.

Reference
---------

.. automodule:: ndn.appv2
    :members:
