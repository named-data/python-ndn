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
from typing import Optional

from ...encoding import BinaryStr
from ...encoding.tlv_model_v2 import tlv_encode, tlv_parse


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
    value: Optional[bytes] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.COMPONENT_VALUE})
    # Referring to a previous matched pattern
    tag: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.PATTERN_TAG})


@dc.dataclass
class UserFnCall:
    fn_id: Optional[str] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.USER_FN_ID})
    args: list[UserFnArg] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.FN_ARGS})


@dc.dataclass
class ConstraintOption:
    # Equal to a given NameComponent value
    value: Optional[bytes] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.COMPONENT_VALUE})
    # Equal to another pattern
    tag: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.PATTERN_TAG})
    # Decide by a user function call
    fn: Optional[UserFnCall] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.USER_FN_CALL})


@dc.dataclass
class PatternConstraint:
    options: list[ConstraintOption] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.CONS_OPTION})


@dc.dataclass
class PatternEdge:
    dest: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.NODE_ID})
    tag: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.PATTERN_TAG})
    cons_sets: list[PatternConstraint] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.CONSTRAINT})


@dc.dataclass
class ValueEdge:
    dest: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.NODE_ID})
    value: Optional[bytes] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.COMPONENT_VALUE})


@dc.dataclass
class Node:
    id: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.NODE_ID})
    parent: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.PARENT_ID})
    rule_name: list[str] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.IDENTIFIER})
    v_edges: list[ValueEdge] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.VALUE_EDGE})
    p_edges: list[PatternEdge] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.PATTERN_EDGE})
    sign_cons: list[int] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.KEY_NODE_ID})


@dc.dataclass
class TagSymbol:
    tag: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.PATTERN_TAG})
    ident: Optional[str] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.IDENTIFIER})


@dc.dataclass
class LvsModel:
    version: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.VERSION})
    start_id: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.NODE_ID})
    named_pattern_cnt: Optional[int] = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.NAMED_PATTERN_NUM})
    nodes: list[Node] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.NODE})
    symbols: list[TagSymbol] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.TAG_SYMBOL})

    def encode(self) -> bytearray:
        return tlv_encode(self)

    @classmethod
    def parse(cls, wire: BinaryStr) -> 'LvsModel':
        return tlv_parse(cls, wire)
