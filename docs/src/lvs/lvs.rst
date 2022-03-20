Light VerSec
============

Introduction
------------

Light VerSec (LVS) is a domain-specific language used to describe trust schemas in NDN.
It originates from `VerSec <https://github.com/pollere/DCT/blob/main/tools/compiler/doc/language.md>`_,
designed and implemented by Pollere, Inc.
Based on pattern matching, the VerSec language allows to express signing relations between name patterns,
and the VerSec library can use it to validate trust schema at compile-time,
check if the signing key of a packet received is allowed to sign that packet,
and infer proper key or certificate to use when producing data.
LVS is a lightweight modification of VerSec that focuses on signing key validation.

Quick Example
-------------

The following example descrive a trust schema of a blog website:

.. code-block:: python3

    from ndn.app_support.light_versec import compile_lvs, Checker

    lvs_text = r'''
    // Site prefix is "/a/blog"
    #site: "a"/"blog"
    // The trust anchor name is of pattern /a/blog/KEY/<key-id>/<issuer>/<cert-id>
    #root: #site/#KEY
    // Posts are signed by some author's key
    #article: #site/"article"/category/year/month <= #author
    // An author's key is signed by an admin's key
    #author: #site/role/author/#KEY & { role: "author" } <= #admin
    // An admin's key is signed by the root key
    #admin: #site/"admin"/admin/#KEY <= #root

    #KEY: "KEY"/_/_/_
    '''
    lvs_model = compile_lvs(lvs_text)

Once the LVS text schema is compiled into a binary model, one can use it to check matching relations:

.. code-block:: python3

    checker = Checker(lvs_model, {})
    # Xinyu's author key can sign an article
    print(checker.check('/a/blog/article/math/2022/03',
                        '/a/blog/author/xinyu/KEY/1/admin/1'))  # => True
    # Admin's key can sign Xinyu's author key
    print(checker.check('/a/blog/author/xinyu/KEY/1/admin/1',
                        '/a/blog/admin/admin/KEY/1/root/1'))  # => True
    # Root key cannot directly sign author's key
    print(checker.check('/a/blog/author/xinyu/KEY/1/admin/1',
                        '/a/blog/KEY/1/self/1'))  # => False

Syntax and Semantics
--------------------

Pattern
~~~~~~~

A *component pattern* or *pattern* for short is a named variable
that captures one arbitrary name component.
In LVS, a component pattern is represented by a C-style identifier.
A *name pattern* is a sequence of name components and component patterns,
which can be used to match an NDN name.
In LVS, name component values are put into quotes.
For example, ``/"ndn"/user/"KEY"/key_id`` is a name pattern which has
two component values (``ndn`` and ``KEY``) and
two patterns (``user`` and ``key_id``).

When a name pattern matches a name,
the name must have the same length as the name pattern,
and every valued component must be exactly the same as
components in the name at the same places.
For example,
the name pattern above matches with names ``/ndn/xinyu/KEY/1`` and
``/ndn/admin/KEY/65c66a2a``,
but it does not match with ``/ndn/xinyu/key/1`` or
``/ndn/xinyu/KEY/1/self/1``.

In a matching, a component pattern can match only one arbitrary component,
even the pattern occurs more than once.
For example, name pattern ``/a/"b"/a/d``
can match with name ``/x/b/x/ddd`` but not name ``/x/b/y/ddd``.

In LVS, you can embed a rule in a name pattern.
For example, if ``#ndn`` is defined to be ``/"ndn"``
and ``#key`` is defined to be ``/"KEY"/key_id``,
then the above name pattern can be written as
``#ndn/user/#key`` for short.

Rule
~~~~

A *rule* is a name pattern with *component constraints* and *signing constraints*.
It has format:

.. code-block:: text

    #rule-name: name-pattern & component-constraints <= signing-constraints

A *component constraint* restricts how a pattern can match with a component.
A *signing constraint* defines names of keys that can be used to sign packets matching with this rule.
In the previous example,
``{ role: "author" }`` is a component constraint,
that limits the pattern named ``role`` can only match with component ``"author"``.
``#author: ... <= #admin`` is a signing constraint,
which says an author's key must be signed by an admin's key.

Component constraints
"""""""""""""""""""""

A set of component constraints basically has a format as follows:

.. code-block:: text

    {pattern_1: constraint_1, pattern_2: constraint_2, ..., pattern_n: constraint_n}

A name must satisfy all constraints required in a constraint set to be matched with a name pattern.

LVS supports three different type of component constraints:
component values, patterns, and user functions.
A component value restricts the pattern variable to only match with a given component value,
like ``{ role: "author" }``.
If another pattern name is used as a constraint,
the current pattern must have the same value as the given pattern.
For example, the name pattern with constraint ``/a/"b"/c/d & {c: a}``
is equivalent to the aforementioned name pattern ``/a/"b"/a/d``,
as pattern ``c`` is required to equal ``a``.
A user function allows user to use some Python function to decide whether a value matches.

LVS allows a constraint to take multiple options, separated by ``|``.
For example, ``{ role: "author"|"admin" }`` means ``role`` can match with
either ``author`` or ``admin``.
Different options may have different types.
Also, LVS allows multiple constraint sets to be given to a rule, separated by ``|``.
In that case, any constraint set holds will lead to a successful matching.
For example, the following two rules:

.. code-block:: text

    #user1: #site/role/user/#KEY & { role: "author"|"admin" }
    #user2: #site/role/user/#KEY & { role: "author" } | { role: "admin" }

mean the same thing: a key name of either an author or an admin user.

If a rule's name pattern refers to other rules,
the component constraints of those rules will be inherited.
In the example above, ``#user1`` and ``#user2`` will inherit all component constraints of ``#site``
and ``#KEY``.
A rule may also add complementary constraints to the patterns inherited.
For example, if ``#KEY`` has a component pattern named ``key-id``,
then ``#user1`` can add a constraint like ``{ key-id: "1" }``.

Signing constraints
"""""""""""""""""""

A signing constraint suggests a name pattern of a key that can be used to sign the packet matching with the rule.
A rule can have multiple signing constraints, separated by ``|``.
Note that LVS does not allow giving name patterns or component constraints directly as a signing constraint.

A matched pattern is carried over through a signing chain.
For example:

.. code-block:: text

    #post: #site/"post"/author/date <= #author | #admin
    #author: #site/"author"/author/#KEY <= #admin
    #admin: #site/"admin"/admin/#KEY <= #root

This means a post must be signed by an author with the same ``author`` in the name,
or an arbitrary admin.
For example, ``/site/post/xinyu/2022`` can only be signed with ``/site/author/xinyu/KEY``
but not ``/site/author/zhiyi/KEY``, because he is not the author of this post and the pattern
``author`` does not match with the same pattern in the post name.
However, if Zhiyi has an admin key, he can use
``/site/admin/zhiyi/KEY`` to sign the post without any issue.

.. warning::

    A component constraint can only refer to **previous defined** pattern,
    either from a previous component or from the rule signed by the current one.
    For example, ``/a/b/c & {b: c}`` will match nothing by itself,
    because ``c`` does not have a value when ``b`` is matched.
    Consider write ``/a/b/c & {c: b}`` instead.
    On the other hand, ``#r1: /a/b & {b: c}`` is valid if there is another rule
    ``#r2: /c/d <= #r1``, when validating ``#r2``'s signature,
    as ``c`` is matched in ``#r2``'s name, and the matching is carried over to ``#r1``'s matching.
    However, in this case, no key can sign ``#r1``,
    so there must be another rule describing how the keys are further signed.

User Functions
~~~~~~~~~~~~~~

User functions are named in the format of ``$function``.
They should be provided by the application code using the trust schema.
A user function can take arguments of type component values and patterns.
For example, ``$fn("component", pattern)`` is a valid function call.
When used as a component constraint,
the LVS library will always call the user function with two arguments:
the first one is the value of the pattern constrained,
and the second one is a list containing all arguments.
For example,

.. code-block:: text

    #rule: /a/b & { b: $fn("c", a) }

If we match it with name ``/x/y``, the LVS library will call
``$fn`` with argument ``("y", ["c", "x"])`` when the matching process reaches ``b``.

Temporary Identifiers
~~~~~~~~~~~~~~~~~~~~~

Identifiers starting with an underscore ``_`` are temporary identifiers.
For example, ``$_RULE`` and ``_PATTERN``,
and even ``$_`` and ``_``.
As the name says, temporary identifiers are not memorized and thus cannot be referred to.
Instead, it is safe to reuse temporary identifiers as many times and they won't interfere each other.
It is supposed to be used when one doesn't want to give a name,
doesn't care the values, or used to avoid name collisions.

A temporary rule ``$_RULE`` can be defined as many times.
But it is not allowed to be used in a name pattern like ``/$_RULE/"component"``.

A temporary pattern ``_pattern`` occuring in a name pattern does **not** need to match with a unique value.
In the previous example, ``#KEY: "KEY"/_/_/_`` can match with names like
``KEY/1/self/1``, and there is no need for the last three components to be the same.
A temporary pattern can be constrained, but it cannot occur on the right hand side of a component constraint
of another pattern.

Formal Grammar
--------------

The formal grammar of LVS is defined as follows:

.. code-block:: ebnf

    TAG_IDENT = CNAME;
    RULE_IDENT = "#", CNAME;
    FN_IDENT = "$", CNAME;

    name = ["/"], component, {"/", component};
    component = STR
              | TAG_IDENT
              | RULE_IDENT;

    definition = RULE_IDENT, ":", def_expr;
    def_expr = name, ["&", comp_constraints], ["<=", sign_constraints];
    sign_constraints = RULE_IDENT, {"|", RULE_IDENT};
    comp_constraints = cons_set, {"|", cons_set};
    cons_set = "{", cons_term, {",", cons_term}, "}";
    cons_term = TAG_IDENT, ":", cons_expr;
    cons_expr = cons_option, {"|", cons_option};
    cons_option = STR
                | TAG_IDENT
                | FN_IDENT, "(", fn_args, ")";
    fn_args = (STR | TAG_IDENT), {",", (STR | TAG_IDENT)};

    file_input = {definition};

See the source code for the grammar used by Lark parser.

References
----------

.. automodule:: ndn.app_support.light_versec

    .. autofunction:: compile_lvs

    .. autoclass:: Checker
        :members:

    .. autoclass:: SemanticError
        :members:

    .. autoclass:: LvsModelError
        :members:

.. autonewtypedata:: ndn.app_support.light_versec.checker.UserFn

