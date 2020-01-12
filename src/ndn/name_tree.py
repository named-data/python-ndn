# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 Xinyu Ma
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
import asyncio as aio
from pygtrie import Trie
from typing import List, Optional, Tuple, Dict
from .encoding import InterestParam, FormalName
from .types import InterestNack, Validator, Route


class NameTrie(Trie):
    def _path_from_key(self, key: FormalName) -> FormalName:
        # bytes(x) will copy x if x is memoryview or bytearray but will not copy bytes
        return [x if isinstance(x, memoryview) and x.readonly else bytes(x)
                for x in key]

    def _key_from_path(self, path: FormalName) -> FormalName:
        return path


class InterestTreeNode:
    pending_list: List[Tuple[aio.Future, int, bool, bool]] = None

    def __init__(self):
        self.pending_list = []

    def append_interest(self, future: aio.Future, param: InterestParam):
        self.pending_list.append((future, param.lifetime, param.can_be_prefix, param.must_be_fresh))

    def nack_interest(self, nack_reason: int) -> bool:
        for future, _, _, _ in self.pending_list:
            future.set_exception(InterestNack(nack_reason))
        return True

    def satisfy(self, data, is_prefix: bool) -> bool:
        exact_match_interest = False
        for future, _, can_be_prefix, _ in self.pending_list:
            if can_be_prefix or not is_prefix:
                future.set_result(data)
            else:
                exact_match_interest = True
        if exact_match_interest:
            self.pending_list = [ele for ele in self.pending_list if not ele[2]]
            return False
        else:
            return True

    def timeout(self, future: aio.Future):
        self.pending_list = [ele for ele in self.pending_list if ele[0] is not future]
        return not self.pending_list

    def cancel(self):
        for future, _, _, _ in self.pending_list:
            future.cancel()


class PrefixTreeNode:
    callback: Route = None
    validator: Optional[Validator] = None
    extra_param: Dict = None
