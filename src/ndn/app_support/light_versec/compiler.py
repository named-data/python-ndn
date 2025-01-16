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
from typing import TypeVar, Union, Optional
from dataclasses import dataclass
from . import parser as psr
from . import binary as bny
from .grammar import lvs_grammar

__all__ = ['SemanticError', 'top_order', 'compile_lvs']

T = TypeVar('T')


class SemanticError(Exception):
    """
    Raised when the LVS trust schema to compile has semantic errors.
    """
    pass


def top_order(nodes: set[T], graph: dict[T, list[T]]) -> list[T]:
    """
    Sort nodes of a DAG by its topological order.

    :param nodes: a set containing all nodes
    :param graph: an adjacency list containing all edges
    :return: a sorted list containing all nodes
    """
    in_degs = {n: 0 for n in nodes}
    for (src, edges) in graph.items():
        for dst in edges:
            if src not in nodes or dst not in nodes:
                raise SemanticError(f'Reference relation {src}->{dst} refers to a not existing identifier')
            in_degs[dst] += 1
    ret = []
    while len(ret) < len(nodes):
        cur_round = [n for (n, d) in in_degs.items() if d == 0]
        if not cur_round:
            remaining_nodes = nodes - set(ret)
            raise SemanticError(f'Loop detected for {remaining_nodes}')
        # Sort for stable build. Allowed since T can only be `str` or `int`
        cur_round.sort()
        for n in cur_round:
            for n2 in graph[n]:
                in_degs[n2] -= 1
            in_degs[n] = -1
            ret.append(n)
    return list(reversed(ret))


class Compiler:
    lvs: psr.LvsFile
    rule_ids: list[str]
    rule_refs: dict[str, list[str]]
    named_pats: dict[str, str]
    node_pool: list[bny.Node]
    rule_node_ids: dict[str, list[int]]
    temp_tag_index: int = 0

    @dataclass
    class RuleChain:
        id: str
        name: list[Union[psr.ComponentValue, psr.Pattern]]
        cons_set: list[psr.TagConstraint]
        sign_cons: list[str]

        def pattern_movement(self, depth: int, prev_tags: set[int]) -> tuple[int, list[bny.PatternConstraint], str]:
            if not isinstance(self.name[depth], psr.Pattern):
                return 0, [], ''
            tag = int(self.name[depth].id)
            if tag in prev_tags:
                return tag, [], str(tag) + ':'
            cons_set = []
            cons_set_str = str(tag) + ':'
            for cons in self.cons_set:
                if tag not in set(int(x) for x in cons.pat.id.split(' ')):
                    continue
                encoded_cons = bny.PatternConstraint()
                encoded_cons.options = []
                cons_set_str += '{'
                for opt in cons.options:
                    encoded_opt = bny.ConstraintOption()
                    if isinstance(opt, psr.ComponentValue):
                        encoded_opt.value = opt.c
                        cons_set_str += 'v=' + opt.c.hex()
                    elif isinstance(opt, psr.Pattern):
                        encoded_opt.tag = int(opt.id)
                        cons_set_str += 't=' + opt.id
                    elif isinstance(opt, psr.FnCall):
                        encoded_opt.fn = bny.UserFnCall()
                        encoded_opt.fn.fn_id = opt.fn
                        cons_set_str += opt.fn + '('
                        encoded_opt.fn.args = []
                        for arg in opt.args:
                            encoded_arg = bny.UserFnArg()
                            if isinstance(arg, psr.ComponentValue):
                                encoded_arg.value = arg.c
                                cons_set_str += 'v=' + arg.c.hex()
                            else:
                                assert isinstance(arg, psr.Pattern)
                                encoded_arg.tag = int(arg.id)
                                cons_set_str += 't=' + arg.id
                            encoded_opt.fn.args.append(encoded_arg)
                        cons_set_str += ')'
                    encoded_cons.options.append(encoded_opt)
                    cons_set_str += ','
                cons_set_str += '}'
                cons_set.append(encoded_cons)
            return tag, cons_set, cons_set_str

    rep_rules: dict[str, list[RuleChain]]

    def __init__(self, lvs: psr.LvsFile):
        self.lvs = lvs

    def _sort_rule_references(self):
        rule_id_set = set()
        temp_rule_number = 1
        for rule in self.lvs.rules:
            # if rule.id.id[1] != '_':
            #     if rule.id.id in rule_id_set:
            #         raise SemanticError(f'Rule {rule.id.id} is redefined')
            # else:
            #     rule.id.id += f'#{temp_rule_number}'
            #     temp_rule_number += 1
            if rule.id.id[1] == '_':
                rule.id.id += f'#{temp_rule_number}'
                temp_rule_number += 1
            rule_id_set.add(rule.id.id)
        adj_lst = {r: [] for r in rule_id_set}
        for rule in self.lvs.rules:
            for c in rule.name.p:
                if isinstance(c, psr.RuleId):
                    if c.id not in rule_id_set:
                        raise SemanticError(f'Rule {rule.id.id} refers to a non-existing rule {c.id}')
                    if c.id[1] == '_':
                        raise SemanticError(f'Rule {rule.id.id} refers to a temporary rule {c.id}')
                    adj_lst[rule.id.id].append(c.id)
        self.rule_ids = top_order(rule_id_set, adj_lst)
        self.rule_refs = adj_lst
        # Sort rules
        idx_lookup = {rule_id: idx for (idx, rule_id) in enumerate(self.rule_ids)}
        self.lvs.rules.sort(key=lambda r: idx_lookup[r.id.id])

    def _gen_pattern_numbers(self):
        self.named_pats = {}
        # id of next named/normal pattern
        next_named = 1
        # id of next temporary pattern
        next_temp = -1
        # First number rule names
        for rule in self.lvs.rules:
            temp_pats = {}
            # First number all patterns in name
            for c in rule.name.p:
                if not isinstance(c, psr.Pattern):
                    continue
                # Note: this function will turn Pattern.id from an identifier into "int" or "[int]"
                pid = c.id
                if pid[0] == '_':
                    # Always allocate a new number for temporary pattern
                    c.id = str(next_temp)
                    next_temp -= 1
                    if pid not in temp_pats:
                        temp_pats[pid] = [c.id]
                    else:
                        temp_pats[pid].append(c.id)
                else:
                    # Try to get existing number. If fails, get a new one
                    if pid in self.named_pats:
                        c.id = self.named_pats[pid]
                    else:
                        c.id = str(next_named)
                        next_named += 1
                        self.named_pats[pid] = c.id
            # Now adapt constraints
            for cons_set in rule.comp_cons:
                for cons in cons_set:
                    try:
                        if cons.pat.id[0] == '_':
                            cons.pat.id = ' '.join(str(x) for x in temp_pats[cons.pat.id])
                        else:
                            cons.pat.id = self.named_pats[cons.pat.id]
                        for op in cons.options:
                            if isinstance(op, psr.Pattern):
                                if op.id[0] != '_':
                                    op.id = self.named_pats[op.id]
                                else:
                                    raise SemanticError(f'Temporary pattern {op.id} cannot be used '
                                                        f'on the right hand side of any pattern constraint')
                            elif isinstance(op, psr.FnCall):
                                for arg in op.args:
                                    if isinstance(arg, psr.Pattern):
                                        if arg.id[0] != '_':
                                            arg.id = self.named_pats[arg.id]
                                        else:
                                            raise SemanticError(f'Temporary pattern {arg.id} cannot be used '
                                                                f'on the right hand side of any pattern constraint')
                    except (KeyError, IndexError):
                        raise SemanticError(f'Pattern {cons.pat.id} never occurs before.')

    def _replicate_rules(self):
        self.rep_rules = {}
        for rule in self.lvs.rules:
            sign_cons = sorted([s.id for s in rule.sign_cons])
            if not rule.comp_cons:
                cur_chains = [self.RuleChain(id=rule.id.id, name=[], cons_set=[], sign_cons=sign_cons)]
            else:
                cur_chains = [self.RuleChain(id=rule.id.id, name=[], cons_set=cons, sign_cons=sign_cons)
                              for cons in rule.comp_cons]
            for comp in rule.name.p:
                if isinstance(comp, (psr.Pattern, psr.ComponentValue)):
                    for chain in cur_chains:
                        chain.name.append(comp)
                else:
                    # Note: this repeats temporary tag numbers, which needs to be fixed before emit.
                    new_chains = [self.RuleChain(id=rule.id.id,
                                                 name=chain.name+ref_chain.name,
                                                 cons_set=chain.cons_set+ref_chain.cons_set,
                                                 sign_cons=chain.sign_cons)
                                  for ref_chain in self.rep_rules[comp.id]
                                  for chain in cur_chains]
                    assert len(new_chains) > 0
                    cur_chains = new_chains
            if rule.id.id not in self.rep_rules:
                self.rep_rules[rule.id.id] = cur_chains
            else:
                self.rep_rules[rule.id.id] += cur_chains

    def _generate_node(self, depth: int, context: list[RuleChain], parent: Optional[int],
                       previous_tags: set[int]) -> int:
        node = bny.Node()
        node.id = len(self.node_pool)
        self.node_pool.append(node)
        node.parent = parent
        # Resolve the end of chains
        new_context = []
        node.rule_name = []
        node.sign_cons = []
        for rc in context:
            if depth == len(rc.name):
                node.rule_name.append(rc.id)
                # Here we violate the type (expected list[int], actual list[str]).
                # Will fix it later in `_fix_signing_references`
                node.sign_cons.extend(rc.sign_cons)
                if rc.id not in self.rule_node_ids:
                    self.rule_node_ids[rc.id] = [node.id]
                else:
                    self.rule_node_ids[rc.id].append(node.id)
            else:
                new_context.append(rc)
        context = new_context
        # Value movements
        v_move = set(rc.name[depth].c for rc in context
                     if isinstance(rc.name[depth], psr.ComponentValue))
        node.v_edges = []
        v_move_list = sorted(list(v_move))
        for v in v_move_list:
            new_context = [rc for rc in context
                           if isinstance(rc.name[depth], psr.ComponentValue)
                           and rc.name[depth].c == v]
            edge = bny.ValueEdge()
            edge.value = v
            edge.dest = self._generate_node(depth + 1, new_context, node.id, previous_tags)
            node.v_edges.append(edge)
        # Pattern movements
        p_moves = [rc.pattern_movement(depth, previous_tags) + (rc,) for rc in context
                   if isinstance(rc.name[depth], psr.Pattern)]
        p_move_strs = sorted(list(set(pm[2] for pm in p_moves)))
        for pm_str in p_move_strs:
            new_context = [pm[3] for pm in p_moves if pm[2] == pm_str]
            assert len(new_context) > 0
            tag = next(pm[0] for pm in p_moves if pm[2] == pm_str)
            edge = bny.PatternEdge()
            if tag >= 0:
                edge.tag = tag
            else:
                # TLV integer is required to be unsigned, so we use maximum named pattern + x for temporary pattern -x
                self.temp_tag_index += 1
                edge.tag = self.temp_tag_index
                # edge.tag = len(self.named_pats) - tag
            edge.cons_sets = next(pm[1] for pm in p_moves if pm[2] == pm_str)
            edge.dest = self._generate_node(depth + 1, new_context, node.id, previous_tags | {tag})
            node.p_edges.append(edge)
        return node.id

    def _fix_signing_references(self):
        """
        Convert signing constraints from string node-ID to integer node-ID
        """
        for node in self.node_pool:
            sign_cons = node.sign_cons
            if not sign_cons:
                continue
            new_sign_cons = []
            for rid in sign_cons:
                if rid not in self.rule_node_ids:
                    raise SemanticError(f'Signed by a non-existing key {rid}')
                new_sign_cons.extend(self.rule_node_ids[rid])
            node.sign_cons = sorted(new_sign_cons)

    def compile(self) -> bny.LvsModel:
        self._sort_rule_references()
        self._gen_pattern_numbers()
        self._replicate_rules()
        self.node_pool = []
        self.rule_node_ids = {}
        # Sort replicated rules for compilation stability
        sorted_rep_rules = list(self.rep_rules.items())
        sorted_rep_rules.sort(key=lambda tup: tup[0])
        rule_chains = sum([v for (k, v) in sorted_rep_rules], start=[])
        self.temp_tag_index = len(self.named_pats)
        start_node = self._generate_node(0, rule_chains, None, set())
        self._fix_signing_references()
        ret = bny.LvsModel()
        ret.version = bny.VERSION
        ret.start_id = start_node
        ret.named_pattern_cnt = len(self.named_pats)
        ret.nodes = self.node_pool
        symbols = []
        for pname, number in self.named_pats.items():
            symbol = bny.TagSymbol()
            symbol.ident = pname
            symbol.tag = int(number)
            symbols.append(symbol)
        symbols.sort(key=lambda sym: sym.tag)
        ret.symbols = symbols
        return ret


def compile_lvs(lvs_text: str) -> bny.LvsModel:
    """
    Compile a text Light VerSec file into a TLV encodable binary LVS model.
    The latter one can be used to create validators.

    :param lvs_text: Light VerSec text file
    :return: LVS model
    :raises SemanticError: when the given text file has a semantic error
    :raises lark.UnexpectedInput: when the given text file has a syntax error
    """
    parser = lark.Lark(lvs_grammar, parser='lalr', transformer=psr.Parser())
    lvs_file: psr.LvsFile = parser.parse(lvs_text)
    compiler = Compiler(lvs_file)
    return compiler.compile()
