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
import logging
from ..encoding import FormalName, Name, BinaryStr, InterestParam
from ..name_tree import NameTrie
from .schema_tree import MatchedNode
from . import policy


class MemoryCache:
    """
    MemoryCache is a simple cache class that supports searching and storing Data packets in the memory.
    """
    def __init__(self):
        self.data = NameTrie()

    async def search(self, name: FormalName, param: InterestParam):
        """
        Search for the data packet that satisfying an Interest packet with name specified.

        :param name: the Interest name.
        :param param: the parameters of the Interest. Not used in current implementation.
        :return: a raw Data packet or None.
        """
        try:
            return next(self.data.itervalues(prefix=name, shallow=True))
        except KeyError:
            logging.getLogger(__name__).debug(f'Cache miss: {Name.to_str(name)}')
            return None

    async def save(self, name: FormalName, packet: BinaryStr):
        """
        Save a Data packet with name into the memory storage.

        :param name: the Data name.
        :param packet: the raw Data packet.
        """
        logging.getLogger(__name__).debug(f'Cache save: {Name.to_str(name)}')
        self.data[name] = bytes(packet)


class MemoryCachePolicy(policy.Cache):
    """
    MemoryCachePolicy stores Data packets in memory.
    """
    def __init__(self, cache):
        super().__init__()
        self.cache = cache

    async def search(self, match: MatchedNode, name: FormalName, param: InterestParam):
        return await self.cache.search(name, param)

    async def save(self, match: MatchedNode, name: FormalName, packet: BinaryStr):
        await self.cache.save(name, packet)
