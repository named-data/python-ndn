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

from typing import Callable, Iterator

from ...encoding import BinaryStr, Component, FormalName, Name, NonStrictName
from ...security import Keychain
from ..security_v2 import parse_certificate
from . import binary as bny
from .compiler import top_order


__all__ = ["UserFn", "LvsModelError", "Checker", "DEFAULT_USER_FNS"]


UserFn = Callable[[BinaryStr, list[BinaryStr]], bool]
r"""
A UserFn represents a LVS user function. It takes two arguments:
the first one is the value of the constrained pattern;
the second one is a list consists of all input parameters in the LVS trust schema.
"""


class LvsModelError(Exception):
    """
    Raised when the input LVS model is malformed.
    """

    pass


class Checker:
    """
    A checker uses a LVS model to match names and checks if a key name is allowed to sign a packet.

    :ivar model: the LVS model used.
    :ivar user_fns: user functions
    """

    model: bny.LvsModel  # NOTE: working on binary model is less efficient
    user_fns: dict[str, UserFn]
    _model_fns: set[str]
    _trust_roots: set[str]
    _symbols: dict[int, str]
    _symbol_inverse: dict[str, int]

    def __init__(self, model: bny.LvsModel, user_fns: dict[str, UserFn]):
        self.model = model
        self.user_fns = user_fns
        self._symbols = {s.tag: s.ident for s in self.model.symbols}
        self._symbol_inverse = {s.ident: s.tag for s in self.model.symbols}
        self._sanity_check()

    def _sanity_check(self):
        """Basic sanity check. Also collect info for other testing."""
        if (
            self.model.version is None
            or not bny.MIN_SUPPORTED_VERSION <= self.model.version <= bny.VERSION
        ):
            raise LvsModelError(f"Unsupported LVS model version {self.model.version}")
        self._model_fns = set()
        self._trust_roots = set()
        in_deg_nodes = set()
        adj_lst = {n.id: [] for n in self.model.nodes}
        nodes_id_lst = set(adj_lst.keys())

        def dfs(cur, par):
            if cur >= len(self.model.nodes):
                raise LvsModelError(f"Non-existing node id {cur}")
            node = self.model.nodes[cur]
            if node.id != cur:
                raise LvsModelError(f"Malformed node id {cur}")
            if par and node.parent != par:
                raise LvsModelError(f"Node {cur} has a wrong parent")
            for ve in node.v_edges:
                if ve.dest is None or not ve.value:
                    raise LvsModelError(f"Node {cur} has a malformed edge")
                dfs(ve.dest, cur)
            for pe in node.p_edges:
                if pe.dest is None or pe.tag is None:
                    raise LvsModelError(f"Node {cur} has a malformed edge")
                dfs(pe.dest, cur)
                for cons in pe.cons_sets:
                    for op in cons.options:
                        branch = [
                            not not op.value,
                            op.tag is not None,
                            op.fn is not None,
                        ].count(True)
                        if branch != 1:
                            raise LvsModelError(
                                f"Edge {cur}->{pe.dest} has a malformed condition"
                            )
                        if op.fn is not None:
                            if not op.fn.fn_id:
                                raise LvsModelError(
                                    f"Edge {cur}->{pe.dest} has a malformed condition"
                                )
                            self._model_fns.add(op.fn.fn_id)
            for key_node_id in node.sign_cons:
                if key_node_id >= len(self.model.nodes):
                    raise LvsModelError(
                        f"Node {cur} is signed by a non-existing key {key_node_id}"
                    )
                in_deg_nodes.add(key_node_id)
                adj_lst[cur].append(key_node_id)

        dfs(self.model.start_id, None)
        top_order(nodes_id_lst, adj_lst)
        self._trust_roots = {
            n for n in in_deg_nodes if not self.model.nodes[n].sign_cons
        }

    def validate_user_fns(self) -> bool:
        """Check if all user functions required by the model is defined."""
        return self._model_fns.issubset(self.user_fns.keys())

    def root_of_trust(self) -> set[str]:
        """
        Return the root of signing chains

        :returns: a set containing rule names for all starting nodes of signing DAG.
        """
        ret = set()
        for cur in self._trust_roots:
            node = self.model.nodes[cur]
            if node.rule_name:
                ret = ret | set(node.rule_name)
            else:
                ret = ret | {"#_" + str(cur)}
        return ret

    def save(self) -> bytes:
        """Save the model to bytes. User functions excluded."""
        return bytes(self.model.encode())

    @staticmethod
    def load(binary_model: BinaryStr, user_fns: dict[str, UserFn]):
        """
        Load a Light VerSec model from bytes.

        :param binary_model: the compiled LVS model in bytes
        :type binary_model: :any:`BinaryStr`
        :param user_fns: user functions
        :type user_fns: dict[str, :any:`UserFn`]
        """
        model = bny.LvsModel.parse(binary_model)
        return Checker(model, user_fns)

    def _context_to_name(self, context: dict[int, BinaryStr]) -> dict[str, BinaryStr]:
        named_tag = {
            self._symbols[tag]: val
            for tag, val in context.items()
            if tag in self._symbols
        }
        annon_tag = {
            str(tag): val for tag, val in context.items() if tag not in self._symbols
        }
        return named_tag | annon_tag

    def _check_cons(
        self,
        value: BinaryStr,
        context: dict[int, BinaryStr],
        cons_set: list[bny.PatternConstraint],
    ) -> bool:
        for cons in cons_set:
            satisfied = False
            for op in cons.options:
                if op.value is not None:
                    if value == op.value:
                        satisfied = True
                        break
                elif op.tag is not None:
                    if value == context.get(op.tag, None):
                        satisfied = True
                        break
                else:
                    fn_id = op.fn.fn_id
                    if fn_id not in self.user_fns:
                        raise LvsModelError(f"User function {fn_id} is undefined")
                    args = [context.get(arg.tag, arg.value) for arg in op.fn.args]
                    if self.user_fns[fn_id](value, args):
                        satisfied = True
                        break
            if not satisfied:
                return False
        return True

    def _match(
        self, name: FormalName, context: dict[int, BinaryStr]
    ) -> Iterator[tuple[int, dict[int, BinaryStr]]]:
        cur = self.model.start_id
        edge_index = -1
        edge_indices = []
        context = context.copy()
        matches = []
        while cur is not None:
            depth = len(edge_indices)
            node = self.model.nodes[cur]
            backtrack = False
            # If match succeeds
            if depth == len(name):
                yield cur, context
                backtrack = True
            else:
                # Make movements
                if edge_index < 0:
                    # Value edge: since it matches at most once, ignore edge_index
                    edge_index = 0
                    for ve in node.v_edges:
                        if name[depth] == ve.value:
                            edge_indices.append(0)
                            matches.append(-1)
                            cur = ve.dest
                            edge_index = -1
                            break
                elif edge_index < len(node.p_edges):
                    # Pattern edge: check condition and make a move
                    pe = node.p_edges[edge_index]
                    edge_index += 1
                    value = name[depth]
                    if pe.tag in context:
                        if value != context[pe.tag]:
                            continue
                        matches.append(-1)
                    else:
                        if not self._check_cons(value, context, pe.cons_sets):
                            continue
                        if pe.tag <= self.model.named_pattern_cnt:
                            context[pe.tag] = value
                            matches.append(pe.tag)
                        else:
                            matches.append(-1)
                    edge_indices.append(edge_index)
                    cur = pe.dest
                    edge_index = -1
                else:
                    backtrack = True
            if backtrack:
                # Backtrack
                if edge_indices:
                    edge_index = edge_indices.pop()
                if matches:
                    last_tag = matches.pop()
                    if last_tag >= 0:
                        del context[last_tag]
                cur = node.parent

    def match(
        self, name: NonStrictName
    ) -> Iterator[tuple[list[str], dict[str, BinaryStr]]]:
        """
        Iterate all matches of a given name.

        :param name: input NDN name.
        :type name: :any:`NonStrictName`
        :return: iterate a pair ``(rule_names, context)``, where ``rule_names`` is a
                 list containing corresponding rule names of current node,
                 and ``context`` is a dict containing pattern->value mapping.
        """
        name = Name.normalize(name)
        if Component.get_type(name[-1]) == Component.TYPE_IMPLICIT_SHA256:
            name = name[:-1]
        for node_id, context in self._match(name, {}):
            node = self.model.nodes[node_id]
            if node.rule_name:
                rule_name = node.rule_name
            else:
                rule_name = ["#_" + str(node_id)]
            yield rule_name, self._context_to_name(context)

    def check(self, pkt_name: NonStrictName, key_name: NonStrictName) -> bool:
        """
        Check whether a packet can be signed by a specified key.

        :param pkt_name: packet name
        :type pkt_name: :any:`NonStrictName`
        :param key_name: key name
        :type key_name: :any:`NonStrictName`
        :return: whether the key can sign the packet
        """
        pkt_name = Name.normalize(pkt_name)
        if Component.get_type(pkt_name[-1]) == Component.TYPE_IMPLICIT_SHA256:
            pkt_name = pkt_name[:-1]
        key_name = Name.normalize(key_name)
        if Component.get_type(key_name[-1]) == Component.TYPE_IMPLICIT_SHA256:
            key_name = key_name[:-1]
        for pkt_node_id, context in self._match(pkt_name, {}):
            pkt_node = self.model.nodes[pkt_node_id]
            for key_node_id, _ in self._match(key_name, context):
                if key_node_id in pkt_node.sign_cons:
                    return True
        return False

    def suggest(self, pkt_name: NonStrictName, keychain: Keychain) -> FormalName:
        """
        Suggest a key from the keychain that is used to sign the specific data packet.

        :param pkt_name: packet name
        :type pkt_name: :any:`NonStrictName`
        :param keychain: keychain
        :type keychain: Keychain
        :return: the first key (in the order of storage) in the keychain that can sign the packet
        """
        pkt_name = Name.normalize(pkt_name)
        for id_name in keychain:
            identity = keychain[id_name]
            for key_name in identity:
                key = identity[key_name]
                for cert_name in key:
                    if self.check(pkt_name, cert_name):
                        cert = parse_certificate(key[cert_name].data)
                        # This is to avoid self-signed certificate
                        if (
                            not cert.signature_info
                            or not cert.signature_info.key_locator
                            or not cert.signature_info.key_locator.name
                        ):
                            continue
                        if self.check(cert_name, cert.signature_info.key_locator.name):
                            return cert_name


DEFAULT_USER_FNS = {
    "$eq": lambda c, args: all(x == c for x in args),
    "$eq_type": lambda c, args: all(
        Component.get_type(x) == Component.get_type(c) for x in args
    ),
}
