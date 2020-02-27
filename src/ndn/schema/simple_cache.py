from ndn.encoding import FormalName, Name, BinaryStr, InterestParam
from ndn.schema.schema_tree import MatchedNode

from . import policy


class MemoryCache:
    def __init__(self):
        self.data = {}

    async def search(self, name: FormalName):
        return self.data.get(Name.to_bytes(name), None)  # Only perfect match

    async def save(self, name: FormalName, packet: BinaryStr):
        self.data[Name.to_bytes(name)] = bytes(packet)


class MemoryCachePolicy(policy.Cache):
    def __init__(self, cache):
        super().__init__()
        self.cache = cache

    async def search(self, match: MatchedNode, name: FormalName, param: InterestParam):
        return await self.cache.search(name)

    async def save(self, match: MatchedNode, name: FormalName, packet: BinaryStr):
        await self.cache.save(name, packet)
