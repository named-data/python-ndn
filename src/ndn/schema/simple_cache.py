from ..encoding import FormalName, Name, BinaryStr, InterestParam
from ..name_tree import NameTrie
from .schema_tree import MatchedNode
from . import policy


class MemoryCache:
    def __init__(self):
        self.data = NameTrie()

    async def search(self, name: FormalName, param: InterestParam):
        try:
            return next(self.data.itervalues(prefix=name, shallow=True))
        except KeyError:
            return None

    async def save(self, name: FormalName, packet: BinaryStr):
        self.data[name] = bytes(packet)


class MemoryCachePolicy(policy.Cache):
    def __init__(self, cache):
        super().__init__()
        self.cache = cache

    async def search(self, match: MatchedNode, name: FormalName, param: InterestParam):
        return await self.cache.search(name, param)

    async def save(self, match: MatchedNode, name: FormalName, packet: BinaryStr):
        await self.cache.save(name, packet)
