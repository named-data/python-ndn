# -----------------------------------------------------------------------------
# This piece of work is inspired by Pollere' VerSec:
# https://github.com/pollere/DCT
# But this code is implemented independently without using any line of the
# original one, and released under Apache License.
#
# Copyright (C) 2019-2022 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
lvs_grammar = r'''
    ?start: file_input

    TAG_IDENT: CNAME
    RULE_IDENT: "#" CNAME
    FN_IDENT: "$" CNAME

    name: "/"? component ("/" component)*
    component: STR        -> component_from_str
             | TAG_IDENT  -> tag_id
             | RULE_IDENT -> rule_id

    definition: RULE_IDENT ":" def_expr
    def_expr: name ("&" comp_constraints)? ("<=" sign_constraints)?
    sign_constraints: RULE_IDENT ("|" RULE_IDENT)*
    comp_constraints: cons_set ("|" cons_set)*
    cons_set: "{" cons_term ("," cons_term)* "}"
    cons_term: TAG_IDENT ":" cons_expr
    cons_expr: cons_option ("|" cons_option)*
    cons_option: STR                      -> component_from_str
               | TAG_IDENT                -> tag_id
               | FN_IDENT "(" fn_args ")" -> fn_call
    fn_args: (STR | TAG_IDENT)? ("," (STR | TAG_IDENT))*

    file_input: definition*

    %import common (DIGIT, LETTER, WS, CNAME, CPP_COMMENT)
    %import common.ESCAPED_STRING -> STR

    %ignore WS
    %ignore CPP_COMMENT
'''
