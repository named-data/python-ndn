# -----------------------------------------------------------------------------
# This piece of is inspired by Adeola Bannis' Boost Info Parser:
# https://gist.github.com/thecodemaiden/dc4e4e4a54eaa5f0be84/
# But this code is implemented independently without using any line of the
# original one, and released under Apache License.
#
# Copyright (C) 2019-2020 The python-ndn authors
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
import shlex


class PropertyNode:
    value: str
    children: dict[str, list[PropertyNode]]

    def __init__(self, value: str = ''):
        self.children = {}
        self.value = value

    def __getitem__(self, key: str) -> list[PropertyNode]:
        return self.children[key]

    def __setitem__(self, key: str, children: list[PropertyNode]):
        self.children[key] = children

    def __delitem__(self, key):
        del self.children[key]

    def insert(self, key: str, child: PropertyNode):
        try:
            self.children[key].append(child)
        except KeyError:
            self.children[key] = [child]

    def _print(self, level: int) -> str:
        ret = f' "{self.value}"\n' if self.value else '\n'
        if self.children:
            ret += ('  ' * level + '{\n') if level >= 0 else ''
            for k, lst in self.children.items():
                for c in lst:
                    ret += '  ' * (level + 1) + k + c._print(level + 1)
            ret += ('  ' * level + '}\n') if level >= 0 else ''
        return ret

    def __str__(self):
        # Print the node as a root
        return self._print(-1)

    def get_node(self, path: str) -> PropertyNode:
        keys = path.split('.')
        cur = self
        for k in keys:
            cur = cur.children[k][0]
        return cur

    def get(self, path: str) -> str:
        return self.get_node(path).value

    def get_default(self, path:str, default: str) -> str:
        try:
            return self.get(path)
        except KeyError:
            return default


class PropertyTree:
    root: PropertyNode

    def __init__(self):
        self.root = PropertyNode()

    def __str__(self):
        return str(self.root).strip()

    @classmethod
    def _parse_children(cls, node, lines: list[str], start_line_no: int) -> int:
        # Remove comments
        last_child = None
        line_no = start_line_no
        while line_no < len(lines):
            line = lines[line_no].split(';')[0].strip()
            line_no += 1
            if not line:
                continue
            while line[-1] == '\\' and line_no < len(lines):
                line = line[:-1] + ' ' + lines[line_no].split(';')[0].strip()
                line_no += 1
            if line == '{':
                if last_child is None:
                    last_child = PropertyNode()
                    node.insert('', last_child)
                line_no = cls._parse_children(last_child, lines, line_no)
            elif line == '}':
                # End of the node. Should quit
                return line_no
            else:
                kv_pair = shlex.split(line)
                key = kv_pair[0]
                child = PropertyNode(value=''.join(kv_pair[1:]))
                node.insert(key, child)
                last_child = child
        return line_no

    @classmethod
    def parse(cls, text: str) -> PropertyTree:
        ret = PropertyTree()
        cls._parse_children(ret.root, text.splitlines(), 0)
        return ret

    @classmethod
    def load(cls, path: str) -> PropertyTree:
        ret = PropertyTree()
        with open(path, 'r') as f:
            cls._parse_children(ret.root, f.readlines(), 0)
        return ret

    def save(self, path: str):
        with open(path, 'w') as f:
            f.write(str(self))
