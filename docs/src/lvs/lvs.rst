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
They should be provided as a dictionary via Checker's construction function by the application code using the trust schema.
The name ``function`` of one user function should be the dictionary key and the corresponding function definition should be the dictionary value.
A user function can take arguments of type component values and patterns.
For example, ``$fn("component", pattern)`` is a valid function call.
When used as a component constraint,
the LVS library will always call the user function with two arguments:
the first one is the value of the pattern constrained,
and the second one is a list containing all arguments.
The return value of one user function should be either ``True`` or ``False``.
For example, there is a user function called ``fn``. It should be defined and provided as follows.

.. code-block:: python3

    def fn(component, pattern):
        if condition:
            return True
        else:
            return False
    user_fn={"fn": fn}
    checker=Checker(lvs_model,user_fn)

In the trust schema, the user function can be called as

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
    CNAME = ? C/C++ identifiers ?;
    STR = ? C/C++ quoted string ?;

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

Tutorial
--------------

Suppose that there is a blog platform that contains three roles: admin, author and reader. It follows these specifications:
1. The prefix of this platform is ``/ndn/blog``. The trust anchor is ``/ndn/blog/KEY/<key-id>/<issuer>/<cert-id>``.
2. There is a root certificate in this platform.
3. Admin has its certificate signed by root certificate.
4. The certificates of both author and reader are signed by admin's certificate.
5. The IDs of both author and reader should be a 6-digit number.
6. Both author and admin can post the articles.
7. The name of a posted article should be ``/ndn/blog/ID/post/<year>/<id>``. The "year" must be a 4-digit number.

Based on the above specifications, the trust schema can be written as:

.. code-block:: text

    // The platform prefix definition. The pair of quotes means that it can only be matched by the identical component.
    #platform: "ndn"/"blog"
    // The certificate name suffix definition. Each underscore can be matched by an arbitrary pattern except that contains slash.
    #KEY: "KEY"/_/_/_
    // The root certificate definition, i.e., /ndn/blog/KEY/<key-id>/<issuer>/<cert-id>.
    #root: #platform/#KEY
    // Admin's certificate definition. The non-sharp patterns, role and adminID, are sent from the application. Each pattern can match an arbitrary components, but the matched components for the same pattern should be the same. The constraint shows that the component "_role" must be "admin". The underscore means that the matched components for the pattern "_role" may not be identical in the chain. The admin's certificate must be signed by the root certificate.
    #admin: #platform/_role/adminID/#KEY & {_role: "admin"} <= #root
    // author's certificate definition. The ID is verified by a user function. Both constraints must be met. It can only be signed by the admin's certificate.
    #author: #platform/_role/ID/#KEY & {_role: "author", ID: $isValidID()} <= #admin
    // author's and reader's certificate definition. The role can be either "reader" or "author". The ID is verified by a user function. Both constraints must be met. It can only be signed by the admin's certificate.
    #user: #platform/_role/ID/#KEY & {_role: "reader"|"author", ID: $isValidID()} <= #admin
    // article's trust schema. The component "year" is verified by a user function. The article can be signed by the admin's certificate or one author's certificate.
    #article: #platform/ID/"post"/year/articleID & {year: $isValidYear()} <= #admin | #author

To build the checker of the above trust schema, we must define the user functions by using lambda expressions first.

.. code-block:: python3

    # Build the dictionary
    user_fn = {
        "$isValidID": lambda component, _pattern: len(Component.get_value(component)) == 6,
        "$isValidYear": lambda component, _pattern: len(Component.get_value(component)) == 4,
    }

With the string of trust schema and the user function dictionary, we can compile the LVS model and initialize the checker.

.. code-block:: python3

    from ndn.app_support.light_versec import compile_lvs, Checker

    lvs_text = r'''
    #platform: "ndn"/"blog"
    #KEY: "KEY"/_/_/_
    #root: #platform/#KEY
    #admin: #platform/_role/adminID/#KEY & {_role: "admin"} <= #root
    #author: #platform/_role/ID/#KEY & {_role: "author", ID: $isValidID()} <= #admin
    #user: #platform/_role/ID/#KEY & {_role: "reader"|"author", ID: $isValidID()} <= #admin
    #article: #platform/ID/"post"/year/articleID & {year: $isValidYear()} <= #admin | #author
    '''

    # compile the LVS model
    lvs_model = compile_lvs(lvs_text)
    # initialize the checker
    checker = Checker(lvs_model, user_fn)

With the function ``check``, we can check whether one name is valid under one certificate name. Here are some testing examples.

.. code-block:: python3

    # Admin's certificate can be signed by the root certificate
    print(checker.check('/ndn/blog/admin/000001/KEY/1/root/1',
                        '/ndn/blog/KEY/1/self/1'))  # => True
    # The component "key" does not match (should be upper-case)
    print(checker.check('/ndn/blog/admin/000001/key/1/root/1',
                        '/ndn/blog/KEY/1/self/1'))  # => False
    # One admin's certificate cannot be signed by another admin.
    print(checker.check('/ndn/blog/admin/000002/KEY/1/root/1',
                        '/ndn/blog/admin/000001/KEY/1/root/1'))  # => False
    # One author's certificate can be signed by an admin (with valid ID).
    print(checker.check('/ndn/blog/author/100001/KEY/1/000001/1',
                        '/ndn/blog/admin/000001/KEY/1/root/1'))  # => True
    # The author's ID is invalid.
    print(checker.check('/ndn/blog/author/1000/KEY/1/000001/1',
                        '/ndn/blog/admin/000001/KEY/1/root/1'))  # => False
    # One reader's certificate can be signed by an admin (with valid ID).
    print(checker.check('/ndn/blog/reader/200001/KEY/1/000001/1',
                        '/ndn/blog/admin/000001/KEY/1/root/1'))  # => True
    # One article can be signed by an author.
    print(checker.check('/ndn/blog/100001/post/2022/1',
                        '/ndn/blog/author/100001/KEY/1/000001/1'))  # => True
    # The author is wrong. The IDs in both article name and certificate name should be the same,
    # as they use the same pattern "ID".
    print(checker.check('/ndn/blog/100001/post/2022/1',
                        '/ndn/blog/author/100002/KEY/1/000001/1'))  # => False
    # The year is invalid.
    print(checker.check('/ndn/blog/100001/post/202/1',
                        '/ndn/blog/author/100001/KEY/1/000001/1'))  # => False
    # The article cannot be signed by a reader.
    print(checker.check('/ndn/blog/200001/post/2022/1',
                        '/ndn/blog/reader/200001/KEY/1/000001/1'))  # => False


References
----------

.. toctree::

    package
    details
    demonstration
    binary-format
