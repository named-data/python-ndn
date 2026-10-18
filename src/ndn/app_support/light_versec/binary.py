# -----------------------------------------------------------------------------
# This piece of work is inspired by Pollere' VerSec:
# https://github.com/pollere/DCT
# But this code is implemented independently without using any line of the
# original one, and released under Apache License.
#
# Copyright (C) 2019-2024 The python-ndn authors
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
import dataclasses as dc
from typing import Self

from ...encoding import BinaryStr
from ...encoding.tlv_model import tlv_encode, tlv_field, tlv_parse


__all__ = [
    "VERSION",
    "TypeNumber",
    "UserFnArg",
    "UserFnCall",
    "ConstraintOption",
    "PatternConstraint",
    "PatternEdge",
    "ValueEdge",
    "Node",
    "TagSymbol",
    "LvsModel",
]


MIN_SUPPORTED_VERSION = 0x00011000
VERSION = 0x00011000


class TypeNumber:
    COMPONENT_VALUE = 0x21
    PATTERN_TAG = 0x23
    NODE_ID = 0x25
    USER_FN_ID = 0x27
    IDENTIFIER = 0x29
    USER_FN_CALL = 0x31
    FN_ARGS = 0x33
    CONS_OPTION = 0x41
    CONSTRAINT = 0x43
    VALUE_EDGE = 0x51
    PATTERN_EDGE = 0x53
    KEY_NODE_ID = 0x55
    PARENT_ID = 0x57
    VERSION = 0x61
    NODE = 0x63
    TAG_SYMBOL = 0x67
    NAMED_PATTERN_NUM = 0x69


@dc.dataclass
class UserFnArg:
    # A given component
    value: bytes | None = tlv_field(
        TypeNumber.COMPONENT_VALUE, default=None)
    # Referring to a previous matched pattern
    tag: int | None = tlv_field(TypeNumber.PATTERN_TAG, default=None)


@dc.dataclass
class UserFnCall:
    fn_id: str | None = tlv_field(TypeNumber.USER_FN_ID, default=None)
    args: list[UserFnArg] = tlv_field(
        TypeNumber.FN_ARGS, default_factory=list)


@dc.dataclass
class ConstraintOption:
    # Equal to a given NameComponent value
    value: bytes | None = tlv_field(
        TypeNumber.COMPONENT_VALUE, default=None)
    # Equal to another pattern
    tag: int | None = tlv_field(TypeNumber.PATTERN_TAG, default=None)
    # Decide by a user function call
    fn: UserFnCall | None = tlv_field(
        TypeNumber.USER_FN_CALL, default=None)


@dc.dataclass
class PatternConstraint:
    options: list[ConstraintOption] = tlv_field(
        TypeNumber.CONS_OPTION, default_factory=list)


@dc.dataclass
class PatternEdge:
    dest: int | None = tlv_field(TypeNumber.NODE_ID, default=None)
    tag: int | None = tlv_field(TypeNumber.PATTERN_TAG, default=None)
    cons_sets: list[PatternConstraint] = tlv_field(
        TypeNumber.CONSTRAINT, default_factory=list)


@dc.dataclass
class ValueEdge:
    dest: int | None = tlv_field(TypeNumber.NODE_ID, default=None)
    value: bytes | None = tlv_field(
        TypeNumber.COMPONENT_VALUE, default=None)


@dc.dataclass
class Node:
    id: int | None = tlv_field(TypeNumber.NODE_ID, default=None)
    parent: int | None = tlv_field(TypeNumber.PARENT_ID, default=None)
    rule_name: list[str] = tlv_field(
        TypeNumber.IDENTIFIER, default_factory=list)
    v_edges: list[ValueEdge] = tlv_field(
        TypeNumber.VALUE_EDGE, default_factory=list)
    p_edges: list[PatternEdge] = tlv_field(
        TypeNumber.PATTERN_EDGE, default_factory=list)
    sign_cons: list[int] = tlv_field(
        TypeNumber.KEY_NODE_ID, default_factory=list)


@dc.dataclass
class TagSymbol:
    tag: int | None = tlv_field(TypeNumber.PATTERN_TAG, default=None)
    ident: str | None = tlv_field(TypeNumber.IDENTIFIER, default=None)


@dc.dataclass
class LvsModel:
    version: int | None = tlv_field(TypeNumber.VERSION, default=None)
    start_id: int | None = tlv_field(TypeNumber.NODE_ID, default=None)
    named_pattern_cnt: int | None = tlv_field(
        TypeNumber.NAMED_PATTERN_NUM, default=None)
    nodes: list[Node] = tlv_field(TypeNumber.NODE, default_factory=list)
    symbols: list[TagSymbol] = tlv_field(
        TypeNumber.TAG_SYMBOL, default_factory=list)

    def encode(self) -> bytearray:
        return tlv_encode(self)

    @classmethod
    def parse(cls, wire: BinaryStr) -> Self:
        return tlv_parse(cls, wire)
