# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
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
import dataclasses as dc
from hashlib import sha256
from typing import Optional
from pygtrie import Trie
from .encoding import InterestParam, FormalName, BinaryStr
from .types import InterestNack, Validator, Route, DataTuple


class NameTrie(Trie):
    def _path_from_key(self, key: FormalName) -> FormalName:
        # bytes(x) will copy x if x is memoryview or bytearray but will not copy bytes
        return [x if isinstance(x, memoryview) and x.readonly else bytes(x)
                for x in key]

    def _key_from_path(self, path: FormalName) -> FormalName:
        return path


@dc.dataclass
class PendingIntEntry:
    future: aio.Future
    lifetime: int
    can_be_prefix: bool
    must_be_fresh: bool
    implicit_sha256: BinaryStr = b''


class InterestTreeNode:
    pending_list: list[PendingIntEntry]

    def __init__(self):
        self.pending_list = []

    def append_interest(self, future: aio.Future, param: InterestParam, implicit_sha256: BinaryStr):
        self.pending_list.append(
            PendingIntEntry(future, param.lifetime,
                            param.can_be_prefix, param.must_be_fresh, implicit_sha256))

    def nack_interest(self, nack_reason: int) -> bool:
        for entry in self.pending_list:
            entry.future.set_exception(InterestNack(nack_reason))
        return True

    def satisfy(self, data: DataTuple, is_prefix: bool) -> bool:
        unsatisfied_entries = []
        raw_packet = data[4]
        for entry in self.pending_list:
            if entry.can_be_prefix or not is_prefix:
                if len(entry.implicit_sha256) > 0:
                    data_sha256 = sha256(raw_packet).digest()
                    passed = data_sha256 == entry.implicit_sha256
                else:
                    passed = True
            else:
                passed = False
            if passed:
                entry.future.set_result(data)
            else:
                unsatisfied_entries.append(entry)
        if unsatisfied_entries:
            self.pending_list = unsatisfied_entries
            return False
        else:
            return True

    def timeout(self, future: aio.Future):
        self.pending_list = [ele for ele in self.pending_list if ele.future is not future]
        return not self.pending_list

    def cancel(self):
        for entry in self.pending_list:
            entry.future.cancel()


class PrefixTreeNode:
    callback: Route = None
    validator: Optional[Validator] = None
    extra_param: dict = None
