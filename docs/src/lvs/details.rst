Implementation Details
======================

This page introduces some implementation details
and some discussion on design for maintainers to understand this work.

Compiler
--------

The goal of compiling is to transform the input rules into a more "clean" graph structure,
so the checker can do matching/verification by traveling along the graph,
with backtracking if necessary.
By doing so, with little sacrifice of flexibility,
we make the checker simpler and more efficient.

To accomplish that goal, the LVS compiler is currently designed as follows:

Input/Output
~~~~~~~~~~~~
`LVS complier <https://python-ndn.readthedocs.io/en/latest/src/lvs/package.html#ndn.app_support.light_versec.compile_lvs>`_
takes string format trust schema written in LVS.

Afterwards, LVS complier outs a name pattern tree using :doc:`TLV Model <../examples/tlv_model>`.
A name pattern tree has the following properties:

* A name pattern tree has a single root.
  Every rule is a path originating from the root.
* Every edge represents a component in name pattern.
* There are two types of edges: edges with a component value; edges representing a pattern.
* Every component constraint is put at the edge representing the pattern it constrains.
  For example, given ``/a/b & {b: "c"}``, we will have a tree:
  ``/ -> /a -> /a/b`` with one constraint ``b = "c"`` put at the edge ``/a->/a/b``.
* Each pattern edge can carry a set of constraints restricting the same pattern,
  with each constraints may have multiple options.
  To move along this edge,
  all constraints in the set must be satisfied by one of its options,
  i.e. CNF formula.
* Signing constraints are put at the end node of a rule,
  in the form of a set referring to the rules that can be used to sign the current name pattern.
* Patterns are stored using numerical IDs (natural numbers).
  An optional symbol table can be provided to store their names before compile.

The detailed format is defined in ``binary.py``.

The LVS compiler does the following steps to generate the name pattern tree:

1. Parse the LVS schema into ASTs
2. Sort rule references.
3. Generate numerical ID for patterns.
4. Replicate rules with multiple constraint sets ``{...}|{...}``,
5. Generate the name pattern tree.
6. Replace rule names in signing constraints with node IDs.
7. Fill in the symbol table for name pattern.

Parsing
~~~~~~~

In python-ndn, LVS is parsed by `Lark <https://lark-parser.readthedocs.io/en/latest/>`_.
The grammar is defined in ``grammar.py``.
Lark's parser allows the user to define a function for every grammar rule,
and calls it at the corresponding reduce step.
These functions are defined in ``parser.py``.
Currently these functions only transform the input AST to some Python classes,
so the LVS compiler can identify the types of terms easily,
e.g., test whether a component in a name pattern is a component value or another rule.
Parser does not do actual compiling work.


Sorting rules
~~~~~~~~~~~~~

LVS allow rules to refer to each other like ``#root: #site/#KEY``.
To effectively expand ``#root`` into a tree path,
we have to expand ``#site`` and ``#KEY`` first.
Therefore, the compiler uses topological sorting to sort rules,
in the reverse order of references.
Cyclic references are also detected at this step.

Generating pattern ID
~~~~~~~~~~~~~~~~~~~~~

At this step, the compiler goes through all rules and constraints to give
every pattern a global unique numerical ID.
IDs are starting from 1.
A named pattern is given the same ID for every occurence.
Every occurence of a temporary pattern is considered as a different pattern,
so it is given a new ID every time.
However, LVS allows the schema to give constraints to temporary patterns.
In that case, the constraint will be replicated.
For example, ``/_a/_a & {_a: $eq_type("v=0")}`` will become
``/1/2 & {1: $eq_type("v=0"), 2: $eq_type("v=0")}``.

Since we don't know the number of named pattern at the beginning,
temporary patterns are numbered with minus number at this time.
They will be turned into positive numbers when outputing the binary schema,
because TLV supports non-negative integers better.

Replicating rules
~~~~~~~~~~~~~~~~~

After compilation, we only check component constraints
at the point a pattern is matched.
However, LVS allows one rule to have multiple constraint sets.
For example, ``/a/b & {a: "a"} | {b: "b"}``.
This disjunctive relation cannot be verified when ``a`` is matched.
Therefore, we replicate a rule with multiple constraint sets.
The rule above will becode ``/a/b & {a: "a"}`` and
``/a/b & {b: "b"}``.
Also, references to other rules are resolved at this step.
In the source code we call a rule after this step a ``chain``.

Generating tree
~~~~~~~~~~~~~~~

This step simply merges all rule chains into a tree,
and put all constraints at the edge of the first occurence of the
constrained pattern.
Note that singing constraints are still referring to rules by their names,
as we have no idea about the ID of the end node of a rule chain.

Fixing signing constraints
~~~~~~~~~~~~~~~~~~~~~~~~~~

Finally, we traverse the tree and replace all name-based signing constraints
with node references.

A workflow demonstration with example trust schema is available
at :doc:`Compiler and Checker Demonstration <./demonstration>`.

Checker
--------
A checker uses a LVS model to match names and checks if a key name is allowed to sign a packet.
Additionally, the caller can supply with some user-defined functions to support customized trust schema checkings (e.g., ``$eq_type("v=0")``).

To match a given name, the checker goes from the tree root,
and recursively goes along edges that are allowed to pass.
When the depth equals to the input name length,
the matching succeeds and returns the end node as well as all matched patterns.
The checker always tries value edges first,
since there is at most one edge that can succeeds.
After all value edges are tried, it tries pattern edges one by one.
When all edges failed, e.g. at a leaf node,
the matching backtracks to the parent node.

Signing key checking
~~~~~~~~~~~~~~~~~~~~
To check whether name A can sign name B (i.e., ``check(pkt_name, key_name)``),
the checker matches the data name B first,
and then tries to the key name A with the context of previous matching.
If B can reach some node in the signing constraint list
of A's matching node, the checker returns true.
False is returned when all possible matches are tried.

Signing key suggesting
~~~~~~~~~~~~~~~~~~~~~~
To suggest a signing key name for packet name A (i.e., ``suggest(pkt_name, keychain)``),
the checker lists all certificats in the local keychain, 
and returns the first certificate name that can satisfy the signing restrictions.
It assumes the corresponding certificate in the keychain is valid.

For example::

  #KEY: "KEY"/_/_/_
  #article: /"article"/_topic/_ & { _topic: "eco" | "spo" } <= #author
  #author: /site/"author"/_/#KEY <= #admin
  #admin: /site/"admin"/_/#KEY <= #anchor
  #anchor: /site/#KEY & {site: "la" | "ny" }

This LVS schema allows both ``/la/author/1`` and ``/ny/author/2`` to sign packet under 
name ``/article/eco/day1``. If both ``/la/author/1`` and ``/ny/author/2`` appears on the 
local keychain, signing suggestion would be the first certificate from the two identities 
that appear in the keychain storage (e.g., ``/la/author/1``).

The ``suggest(pkt_name, keychain)`` itself does not further verify if ``/la/author/1``'s  
certificate signer is legitimate and repeat the same process till the trust anchor.
Instead, it trusts the keychain certificates in any case.

Schema Validation
-----------------

The current things in a LVS trust schema are currently
validated by the compiler or the checker:

* No cyclic references in rule name patterns.
* No cyclic references in signing relations.
* The root of trust (i.e. the starting node of signing chains)
  matches with the name of trust anchor.
* All user functions are provided.


Optimization
------------

This section discusses possible optimizations that may be used.
Note that the content in this section has not been implemented yet.

Merging from the root
~~~~~~~~~~~~~~~~~~~~~

For simplicity of implementation,
the current compiler treats all patterns as different edges.
However, two nodes can be merged if the paths from the root to them have identical
patterns and constraints.
For example, given the schema:

.. code:: text

  #r1 = /"a"/b/c & {b: $fn1(), c: $fn2()}
  #r2 = /"a"/b/c & {b: $fn1(), c: $fn3()}

The current result tree and optimized one are shown in the figure.

.. image:: /_static/lvs-details-opt1.svg
    :align: center
    :width: 50%

Merging from the leaves
~~~~~~~~~~~~~~~~~~~~~~~

If we waive the requirement of tree structure and accepts a DAG,
then another way to simplify the result is to merge
two nodes that have identical subtrees.
This is the same as DFA minimization, so let me omit examples and figures.

Alternative Methods
-------------------

This section lists related work known by the author.
However, at current stage, there lack application scenatios and data
to compare the pros and cons of them.

DFA / NTSchema
~~~~~~~~~~~~~~

The differences between LVS tree and a NTSchema tree is like NFS vs DFA:
a name can have multiple matches in a LVS tree,
but at most one match in NTSchema.

In NTSchema, a pattern edge can only attach a component type,
with out any further constraint.
Every matching step moves along exact one edge,
and never backtracks.
After both the packet name and the key name are matched,
NTSchema checks if the key name matching node is the node specified by ``signed-by``
policy attached at the packet node,
and then checks other conditions.
If the namespace is well-structured and the conditions are simple,
NTSchema should be faster than LVS tree.

It is also possible to convert the LVS tree to a DFA while keeping the behavior to
check conditions as we move.
We can list a truth table for an step with multiple patterns & constraints,
and use something similar to NFA->DFA algorithm
to convert the LVS tree into a deterministic machine.
However, since the number of nodes becomes larger,
whether the performance will be better or not is unknown.

Conceptually,
there is another big difference between LVS and NTSchema:
NTSchema is designed to describe the application name space by cutting it into
subspaces.
Signing relation is just one property that a subspace has.
However, LVS is rule-based,
which means the structure of names in the system is already fixed,
and the user uses this language to express specific rules to
comply with the requirements of signing relations.

Decision-based systems
~~~~~~~~~~~~~~~~~~~~~~

If we consider a name as "a list of values",
the problem can be transformed into a decision making problem:
given variables :math:`x_1,\ldots, x_n, y_1,\ldots, y_m`,
we need to answer a yes-no question based on the truth value
of some propositions like :math:`x_i = v`,
:math:`x_i = y_j`, or :math:`fn(x_i)`.
There are multiple systems can do so.
For example, Prolog allows user to describe logic.
Decision tree, BDD/ZDD can be used to store the logic.
We can even directly store the truth table if it is small.
SAT/SMT can be used to validate the schema.

NDN-CXX Validator
~~~~~~~~~~~~~~~~~

NDN-CXX supports `validator configuration file <https://named-data.net/doc/ndn-cxx/current/tutorials/security-validator-config.html>`_.
It uses a special regular expression to capture names,
which offers best flexibility of my knowledge.
However, the implementation complexity is also very high.

Future Work
-----------

Access control (ABE)
~~~~~~~~~~~~~~~~~~~~

LVS can be extended to describe attributes of packets easily.
However, data -- attribute binding (i.e. "which attribute the data have")
is only part of the access control system.
We also need user -- attribute binding (i.e. "who holds which attribute")
to do access control,
and we believe this binding is out of the scope of this language.
Actually, user -- attribute binding is tightly related to certificate/key issuance,
which is the scope of the trust authority.
