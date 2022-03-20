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
from typing import Callable, Iterator
from ...encoding import Name, BinaryStr, FormalName, NonStrictName
from . import binary as bny


UserFn = Callable[[BinaryStr, list[BinaryStr]], bool]


class Checker:
    model: bny.LvsModel  # NOTE: working on binary model is less efficient
    fns: dict[str, UserFn]
    symbols: dict[int, str]
    symbol_inverse: dict[str, int]

    def __init__(self, model: bny.LvsModel, user_fns: dict[str, UserFn]):
        self.model = model
        self.fns = user_fns
        self.symbols = {s.tag: s.ident for s in self.model.symbols}
        self.symbol_inverse = {s.ident: s.tag for s in self.model.symbols}

    def validate_user_fns(self):
        pass  # TODO

    def root_of_trust(self):
        pass  # TODO

    def _context_to_name(self, context: dict[int, BinaryStr]) -> dict[str, BinaryStr]:
        return ({self.symbols[tag]: val for tag, val in context.items()
                 if tag <= self.model.named_pattern_cnt}
                | {self.symbols[tag]: val for tag, val in context.items()
                   if tag <= self.model.named_pattern_cnt})

    def _check_cons(self, value: BinaryStr, context: dict[int, BinaryStr],
                    cons_set: list[bny.PatternConstraint]) -> bool:
        for cons in cons_set:
            satisfied = False
            for op in cons.options:
                if op.value is not None:
                    if value == op.value:
                        satisfied = True
                        break
                elif op.tag is not None:
                    if value == context.get(op.tag, b''):
                        satisfied = True
                        break
                else:
                    fn_id = op.fn.fn_id
                    if fn_id not in self.fns:
                        raise KeyError(f'User function {fn_id} is undefined')
                    args = [context.get(arg.tag, arg.value) for arg in op.fn.args]
                    if self.fns[fn_id](value, args):
                        satisfied = True
                        break
            if not satisfied:
                return False
        return True

    def _match(self, name: FormalName, context: dict[int, BinaryStr]) -> Iterator[tuple[int, dict[int, BinaryStr]]]:
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
                        context[pe.tag] = value
                        matches.append(pe.tag)
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

    def match(self, name: NonStrictName) -> Iterator[tuple[list[str], dict[str, BinaryStr]]]:
        name = Name.normalize(name)
        for node_id, context in self._match(name, {}):
            node = self.model.nodes[node_id]
            if node.rule_name:
                rule_name = node.rule_name
            else:
                rule_name = ['#_' + str(node_id)]
            yield rule_name, self._context_to_name(context)

    def check(self, pkt_name: NonStrictName, key_name: NonStrictName) -> bool:
        pkt_name = Name.normalize(pkt_name)
        key_name = Name.normalize(key_name)
        for pkt_node_id, context in self._match(pkt_name, {}):
            pkt_node = self.model.nodes[pkt_node_id]
            for key_node_id, _ in self._match(key_name, context):
                if key_node_id in pkt_node.sign_cons:
                    return True
        return False
