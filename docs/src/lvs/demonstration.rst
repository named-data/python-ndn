Compiler and Checker Demonstration
==================================

LVS schema input and parsing
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
We assume the following LVS schema::

  #KEY: "KEY"/_/_/_
  #site: "lvs-test"
  #article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
  #author: #site/"author"/author/"KEY"/_/admin/_ <= #admin
  #admin: #site/"admin"/admin/#KEY <= #root
  #root: #site/#KEY

We ignore the parsing details since this is handled by `Lark <https://lark-parser.readthedocs.io/en/latest/>`_.

Sorting rules
~~~~~~~~~~~~~
The original schema has the following dependencies among the rules::

  (1) #KEY: "KEY"/_/_/_
  (2) #site: "lvs-test"
  (3) #article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
    --> (2) (4)
  (4) #author: #site/"author"/author/"KEY"/_/admin/_ <= #admin
    --> (2) (5)
  (5) #admin: #site/"admin"/admin/#KEY <= #root
    --> (1) (2) (6)
  (6) #root: #site/#KEY
    --> (1) (2)

Topological sorting gives us::

  (3) #article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
    --> (2) (4)
  (4) #author: #site/"author"/author/"KEY"/_/admin/_ <= #admin
    --> (2) (5)
  (5) #admin: #site/"admin"/admin/#KEY <= #root
    --> (1) (2) (6)
  (6) #root: #site/#KEY
    --> (1) (2)
  (1) #KEY: "KEY"/_/_/_
  (2) #site: "lvs-test"

Generating pattern ID
~~~~~~~~~~~~~~~~~~~~~

  #site/"article"/1/2/-1 & {-1: $eq_type("v=0")} <= #author
  #author: #site/"author"/1/"KEY"/-2/3/-3 <= #admin
  #admin: #site/"admin"/3/#KEY <= #root
  #root: #site/#KEY
  #KEY: "KEY"/-4/-5/-6
  #site: "lvs-test"

Replicating rules
~~~~~~~~~~~~~~~~~
In this schema, we don't have have multiple constraint sets like ``/a/b & {a: "a"} | {b: "b"}``.
Therefore, no rule replication is needed.

Generating tree
~~~~~~~~~~~~~~~

.. image:: /_static/lvs-ptree.svg
    :align: center
    :width: 100%

Each node is a name prefix, and edge becoming the condition to 

Fixing signing constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~
.. image:: /_static/lvs-ptree-signing.svg
    :align: center
    :width: 100%

After constructing the tree, the compilier fill in the symbol table for non-temporary symbols::

  1: author
  2: post
  3: admin

and model the name pattern tree into a TLV encodable model.

Checker
~~~~~~~~
In order to check a name ``/lvs-test/article/alice/post1/v=2`` can be signed by 
name ``/lvs-test/author/alice/KEY/%BDA%D6%DE%EA%09%3C%E0/admin/v=1647807153833``, 
Checker first matches ``/lvs-test/article/alice/post1/v=2`` against the name 
pattern tree, which gives the uppermost branch of the pattern tree.

Along the matching, checker fills the symbols with ``author = "alice"`` 
and ``post = "post1"``.
The end of this branch indicates the node identifier (e.g., ``x``) for this branch.

Then the checker matches the ``/lvs-test/author/alice/KEY/...`` 
against the name pattern tree, which gives the second branch from the top.
When matching along this branch, checker uses "alice" for ``1``'s value.
The end of this branch has the same node identifier ``x``, thereby the checking succeeds.