# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
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
from typing import Optional
from ..encoding import NonStrictName, Name, BinaryStr, InterestParam, FormalName
from ..types import Route
from ..name_tree import NameTrie, PrefixTreeNode


class Dispatcher:
    """
    An Interest dispatcher that helps a producer application further dispatches Interests under some route.
    """

    _tree: NameTrie = None

    def __init__(self):
        self._tree = NameTrie()

    def register(self, name: NonStrictName, func: Route):
        """
        Register a callback function. This will not register an NDN route.

        :param name: the name prefix.
        :param func: the callback function.
        :raises ValueError: the name prefix is already registered.
        """
        name = Name.normalize(name)
        node = self._tree.setdefault(name, PrefixTreeNode())
        if node.callback:
            raise ValueError(f'Duplicated registration: {Name.to_str(name)}')
        node.callback = func

    def unregister(self, name: NonStrictName):
        """
        Unregister a callback function.

        :param name: the name prefix.
        """
        name = Name.normalize(name)
        del self._tree[name]

    def dispatch(self, name: FormalName, param: InterestParam, app_param: Optional[BinaryStr]) -> bool:
        """
        Dispatch the Interest to registered callbacks using longest match.

        :return: ``True`` if the Interest is dispatched to some callbacks.
        """
        trie_step = self._tree.longest_prefix(name)
        if not trie_step:
            return False
        trie_step.value.callback(name, param, app_param)
        return True
