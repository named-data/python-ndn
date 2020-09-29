:mod:`ndn.schema` package
============================

.. warning::

    Name Tree Schema (NTSchema) is experimental and capricious.
    The current implementation is treated as a proof-of-concept demo.

Introduction
------------

The :mod:`ndn.schema` package provides an implementation of Name Tree Schema, an application framework that
organizes application functionalities by the applciation namespace.
Modularized NDN libraries can be developed based on it, and
application developers can use those libraries as building blocks.

The core concept of NTSchema is the namespace schema tree.
The schema tree is a tree structure that contains all possible naming conventions of an application.
Different from a tree of names, its edge may be a pattern variable instead of a specific name component.
For example, the path ``/<Identity>/KEY/<KeyID>`` can be used to represents a naming convention of a key,
where specific keys -- like ``/Alice/KEY/%01`` and ``/Bob/KEY/%c2`` match with it.

Two main components of NTSchema are custom nodes and policies.
In the schema tree, every node represents a namespace.
After matching with a specific name, a node can be used to produce and consume data.
For example, if we call ``matched_node = tree.match('/Alice/KEY/%01')``, it will return a matching of node
``/<Identity>/KEY/<KeyID>`` with variable setting ``Identity='Alice', KeyID=\x01``.
Then we call ``matched_node.provide(key_data)``, it will generate the key with data ``key_data`` and make it available.
When we call ``key_data = matched_node.need()``, it will try to fetch the key.
A custom node will have customized pipeline to handle ``provide`` and ``need`` function calls.
Policies are annotations attached to nodes, that specifies user-defined policies that are security, storage, etc.

Examples
--------

.. toctree::

    1 - File Sharing <ex1>

Reference
---------

.. toctree::

    Namespace Schema Tree <schema_tree>
    Utils <utils>
    Custom Nodes <custom_node>
    Policies <policies>
