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
from __future__ import annotations
import lark
from typing import Union
from dataclasses import dataclass
from ...encoding import Component


@dataclass
class ComponentValue:
    c: bytes


@dataclass
class RuleId:
    id: str


@dataclass
class Pattern:
    id: str


@dataclass
class NamePat:
    p: list[Union[ComponentValue, RuleId, Pattern]]


@dataclass
class FnCall:
    fn: str
    args: list[Union[ComponentValue, Pattern]]


@dataclass
class TagConstraint:
    pat: Pattern
    options: list[Union[ComponentValue, Pattern, FnCall]]


@dataclass
class Rule:
    id: RuleId
    name: NamePat
    # A list of component constraint sets.
    # In disjunctive normal form, e.g. (a^b^c)V(d^e)
    comp_cons: list[list[TagConstraint]]
    # A list of signing key names. Any of them can be used.
    sign_cons: list[RuleId]


@dataclass
class LvsFile:
    rules: list[Rule]


class Parser(lark.Transformer):
    name = NamePat
    cons_expr = list
    cons_set = list
    comp_constraints = list
    def_expr = list

    def __init__(self):
        super().__init__()
        self.id_number = 0

    @staticmethod
    def component_from_str(args: list[lark.Token]):
        return ComponentValue(bytes(Component.from_str(args[0].value[1:-1])))

    @staticmethod
    def tag_id(args: list[lark.Token]):
        return Pattern(id=args[0].value)

    @staticmethod
    def rule_id(args: list[lark.Token]):
        return RuleId(id=args[0].value)

    @staticmethod
    def sign_constraints(args: list[lark.Token]):
        return [RuleId(id=t.value) for t in args]

    @staticmethod
    def fn_args(args: list[lark.Token]):
        ret = []
        for t in args:
            if t[0] == '"':
                ret.append(ComponentValue(bytes(Component.from_str(t.value[1:-1]))))
            else:
                ret.append(Pattern(id=t))
        return ret

    @staticmethod
    def fn_call(args):
        return FnCall(fn=args[0].value, args=args[1])

    @staticmethod
    def cons_term(args):
        return TagConstraint(pat=Pattern(id=args[0].value), options=args[1])

    @staticmethod
    def definition(args):
        rule_id = args[0].value
        ret = Rule(id=RuleId(id=rule_id), name=args[1][0], comp_cons=[], sign_cons=[])
        for cons in args[1][1:]:
            if isinstance(cons[0], RuleId):
                ret.sign_cons = cons
            elif isinstance(cons[0], list):
                ret.comp_cons = cons
        return ret

    @staticmethod
    def file_input(args):
        return LvsFile(args)
