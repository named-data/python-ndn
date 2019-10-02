import asyncio as aio
from pygtrie import Trie
from typing import List, Optional, Callable, NoReturn, Tuple
from .encoding import InterestParam, FormalName, MetaInfo, BinaryStr
from .errors import InterestNack, InvalidDataError


class NameTrie(Trie):
    def _path_from_key(self, key: FormalName) -> FormalName:
        # bytes(x) will copy x if x is memoryview or bytearray but will not copy bytes
        return [x if isinstance(x, memoryview) and x.readonly else bytes(x)
                for x in key]

    def _key_from_path(self, path: FormalName) -> FormalName:
        return path


class NameTreeNode:
    registered: bool = False
    on_interest: Optional[Callable[..., NoReturn]] = None
    pending_list: List[Tuple[aio.Future, int, bool, bool]] = None

    def __init__(self):
        self.pending_list = []

    def append_interest(self, future: aio.Future, param: InterestParam):
        self.pending_list.append((future, param.lifetime, param.can_be_prefix, param.must_be_fresh))

    def nack_interest(self, nack_reason: int) -> bool:
        for future, _, _, _ in self.pending_list:
            future.set_exception(InterestNack(nack_reason))
        self.pending_list = []
        return not self.registered

    def satisfy(self, name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr]) -> bool:
        for future, _, _, _ in self.pending_list:
            future.set_result((name, meta_info, content))
        self.pending_list = []
        return not self.registered

    def invalidate(self, name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr]) -> bool:
        for future, _, _, _ in self.pending_list:
            future.set_exception(InvalidDataError(name, meta_info, content))
        self.pending_list = []
        return not self.registered

    def timeout(self, future: aio.Future):
        self.pending_list = [ele for ele in self.pending_list if ele[0] is not future]
        return not self.registered and not self.pending_list
