Binary Format
=============


The format of compiled LVS file is defined as follows.
This page describes version ``0x00011000``.

.. code-block:: abnf

    LvsModel =
         Version
         StartId
         NamedPatternCnt
         *Node
         *TagSymbol

    Version = VERSION-TYPE
              TLV-LENGTH ; == 4
              NonNegativeInteger
    StartId = NODE-ID-TYPE TLV-LENGTH NonNegativeInteger
    NamedPatternCnt = NAMED-PATTERN-NUM-TYPE TLV-LENGTH NonNegativeInteger

    Node = NODE-TYPE TLV-LENGTH
            NodeId
            [Parent]
            *RuleName
            *ValueEdge
            *PatternEdge
            *SignConstraint

    NodeId = NODE-TYPE TLV-LENGTH NonNegativeInteger
    Parent = NODE-TYPE TLV-LENGTH NonNegativeInteger
    SignConstraint = KEY-NODE-ID-TYPE TLV-LENGTH NonNegativeInteger
    RuleName = IDENTIFIER-TYPE TLV-LENGTH CNAME
    CNAME = ("_" / ALPHA) *("_" / ALPHA / DIGIT)

    ValueEdge = VALUE-EDGE-TYPE TLV-LENGTH
                Destination
                Value
    Destination = NodeId
    Value = COMPONENT-VALUE-TYPE TLV-LENGTH NameComponent

    PatternEdge = PATTERN-EDGE-TYPE TLV-LENGTH
                    Destination
                    Tag
                    *Constraint
    Tag = PATTERN-TAG-TYPE TLV-LENGTH NonNegativeInteger

    Constraint = CONSTRAINT-TYPE TLV-LENGTH *ConstraintOption
    ConstraintOption = CONS-OPTION-TYPE TLV-LENGTH (Value / Tag / UserFnCall)

    UserFnCall = USER-FN-CALL-TYPE TLV-LENGTH
                FnId
                *UserFnArg
    FnId = USER-FN-ID-TYPE TLV-LENGTH CNAME
    UserFnArg = USER-FN-ARG-TYPE TLV-LENGTH (Value / Tag)

    TagSymbol = TAG-SYMBOL-TYPE TLV-LENGTH
                Tag
                Identifier

    Identifier = IDENTIFIER-TYPE TLV-LENGTH CNAME


TLV numbers:

.. code-block:: abnf

    COMPONENT-VALUE-TYPE = 0x21
    PATTERN-TAG-TYPE = 0x23
    NODE-ID-TYPE = 0x25
    USER-FN-ID-TYPE = 0x27
    IDENTIFIER-TYPE = 0x29
    USER-FN-CALL-TYPE = 0x31
    FN-ARGS-TYPE = 0x33
    CONS-OPTION-TYPE = 0x41
    CONSTRAINT-TYPE = 0x43
    VALUE-EDGE-TYPE = 0x51
    PATTERN-EDGE-TYPE = 0x53
    KEY-NODE-ID-TYPE = 0x55
    PARENT-ID-TYPE = 0x57
    VERSION-TYPE = 0x61
    NODE-TYPE = 0x63
    TAG-SYMBOL-TYPE = 0x67
    NAMED-PATTERN-NUM-TYPE = 0x69


Explanation
~~~~~~~~~~~

LvsModel
--------

``Version`` is the version number of the LVS model.
Everytime the behavior changes, the version number will increase.
There is no commitment for different versions to implement the same behavior, even the field names are the same.
The application should only accept the model if the version number is recognized.

Every node has an integer ID, which equals to the index it occurs in the LVS model, starting from ``0``.
``StartId`` is the ID of the root Node of the LVS tree.
In current compiler implemented in python-ndn, it is ``0`` to indicate that the first Node is the root,
but there is no guarantee in future and a checker should not rely on this convention.

Every pattern edge is also assigned with a number.
If the number is lower than ``NamedPatternCnt``, then it is a named pattern edge.
If it is larger than or equal to ``NamedPatternCnt``, then it is a temporary named pattern ``_``.
Note that since TLV encoding does not support negative numbers, we use ``NamedPatternCnt`` to differentiate temporary and normal named patterns.
A checker does not need to tell whether a pattern edge is named or not,
if it only checks the signature validity, since every temporary pattern edge is assigned with a different tag.
Tag symbol information is only needed if the checker needs the name identifiers of named patterns.

``TagSymbol`` describes the identifiers for each named pattern edge.
It is ununsed and can be safely discarded if a checker does not dump error reason after verification fails.
The TLV-Type is still marked as critical for sanity check reason expressed in the next section.

Node
----

``NodeId`` always equal to the index it occurs in the LVS model, starting from ``0``.

``RuleName`` is the identifier used to identify this node in the original LVS schema.
It is ununsed if a checker does not dump error reason after verification fails.

``ValueEdge`` and ``PatternEdge`` are edges to children under its subtree.
A ``ValueEdge`` requests an exact match; a ``PatternEdge`` specifies a match of a constraint set,
and assigns the component value to the corresponding pattern variable.
A checker must always check ``ValueEdge`` for exact matches before it uses ``PatternEdge`` to match.
When multiple ``PatternEdge`` can match, the first one occuring in the file should hit.

``SignConstraint`` indicates zero or more node IDs.
When a packet name matches the current node, the signing key should match one of the nodes specified by ``SignConstraint``.
A node without any ``SignConstraint`` implies all signature verification fail on this node,
and thus no packets matching this node should be fetched from network.
The trust anchor can match a node without ``SignConstraint``, as it will never be fetched from network.

Constraint
----------

Constraints only applies to ``PatternEdge`` as conditions.
If specified, each ``PatternEdge`` may have one or multiple constraints and each constraint may have one or multiple constraint options.
The constraints form a conjunctive normal form, i.e. AND of ORs:

- A constraint is satisfied if any of its options is satisfied
- A ``PatternEdge`` is satisfied if all of its constraints are satisfied

Each constraint option can be the form of ``Value`` (which makes it similar to a ``ValueEdge``),
``Tag`` which matches the Component with a previously matched pattern variable,
or a ``UserFn`` which is an external function provided by the application.

Sanity Check
~~~~~~~~~~~~

When loading a compiled LVS model, the following sanity check should be made before executing it.

- ``Version`` is supported.
- Every node's ``NodeId`` equals to its index in the array.
- All edges refer to existing destination node ID.
- Every ``SignConstraint`` refers to an existing destination node ID.
- For each ``ConstraintOption``, exactly one of ``Value``, ``Tag`` and ``UserFn`` is set.
- Every edge's destination sets parent to the source of the edge.
  This guarantees all nodes reachable from the root is a tree.

The following sanity checks are recommended but not required.

- After the application finishes providing user functions, check all user functions used in the programs are given.
  - If the implementation chooses not to do so, it should let the verifcation fail whenever an unknown user function is triggered.
- After the application finishes providing trust anchors, check all leaf nodes without signing constraint are provided with a trust anchor.
  - If the implementation chooses not to do so, it should let the verifcation fail whenever reaches a leaf node without sign constraint.
- No unreachable nodes. (python-ndn does not check this)

User Functions
~~~~~~~~~~~~~~

User functions are provided by the application and there is no guarantee on their exact behavior.
Specific implementations may provide built-in user functions for the application.
However, the application is responsible for the correctness of all user functions used, including built-in ones.
That is to say, different library implementations do not necessarily provide the same set of built-in user functions,
and the application developer is responsible to check if the built-in implementation is correct.

python-ndn provides the following built-in functions:

- ``$eq``: compares two components.
- ``$eq_type``: compares the type of two components.

The details of user functions is up to specific implementation.
