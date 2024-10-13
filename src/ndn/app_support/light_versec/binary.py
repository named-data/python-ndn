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
import ndn.encoding as enc


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


class UserFnArg(enc.TlvModel):
    # A given component
    value = enc.BytesField(TypeNumber.COMPONENT_VALUE)
    # Referring to a previous matched pattern
    tag = enc.UintField(TypeNumber.PATTERN_TAG)


class UserFnCall(enc.TlvModel):
    fn_id = enc.BytesField(TypeNumber.USER_FN_ID, is_string=True)
    args = enc.RepeatedField(enc.ModelField(TypeNumber.FN_ARGS, UserFnArg))


class ConstraintOption(enc.TlvModel):
    # Equal to a given NameComponent value
    value = enc.BytesField(TypeNumber.COMPONENT_VALUE)
    # Equal to another pattern
    tag = enc.UintField(TypeNumber.PATTERN_TAG)
    # Decide by a user function call
    fn = enc.ModelField(TypeNumber.USER_FN_CALL, UserFnCall)


class PatternConstraint(enc.TlvModel):
    options = enc.RepeatedField(
        enc.ModelField(TypeNumber.CONS_OPTION, ConstraintOption)
    )


class PatternEdge(enc.TlvModel):
    dest = enc.UintField(TypeNumber.NODE_ID)
    tag = enc.UintField(TypeNumber.PATTERN_TAG)
    cons_sets = enc.RepeatedField(
        enc.ModelField(TypeNumber.CONSTRAINT, PatternConstraint)
    )


class ValueEdge(enc.TlvModel):
    dest = enc.UintField(TypeNumber.NODE_ID)
    value = enc.BytesField(TypeNumber.COMPONENT_VALUE)


class Node(enc.TlvModel):
    id = enc.UintField(TypeNumber.NODE_ID)
    parent = enc.UintField(TypeNumber.PARENT_ID)
    rule_name = enc.RepeatedField(enc.BytesField(TypeNumber.IDENTIFIER, is_string=True))
    v_edges = enc.RepeatedField(enc.ModelField(TypeNumber.VALUE_EDGE, ValueEdge))
    p_edges = enc.RepeatedField(enc.ModelField(TypeNumber.PATTERN_EDGE, PatternEdge))
    sign_cons = enc.RepeatedField(enc.UintField(TypeNumber.KEY_NODE_ID))


class TagSymbol(enc.TlvModel):
    tag = enc.UintField(TypeNumber.PATTERN_TAG)
    ident = enc.BytesField(TypeNumber.IDENTIFIER, is_string=True)


class LvsModel(enc.TlvModel):
    version = enc.UintField(TypeNumber.VERSION)
    start_id = enc.UintField(TypeNumber.NODE_ID)
    named_pattern_cnt = enc.UintField(TypeNumber.NAMED_PATTERN_NUM)
    nodes = enc.RepeatedField(enc.ModelField(TypeNumber.NODE, Node))
    symbols = enc.RepeatedField(enc.ModelField(TypeNumber.TAG_SYMBOL, TagSymbol))
