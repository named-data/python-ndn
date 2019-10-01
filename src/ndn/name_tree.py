import asyncio as aio
from pygtrie import Trie
from typing import List, Optional, Callable, NoReturn, Coroutine, Tuple
from .encoding import InterestParam, FormalName
from .errors import InterestTimeout, InterestNack


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

    def append_interest(self, future: aio.Future, param: InterestParam) -> Callable[[FormalName], Coroutine]:
        async def wait_for_data(final_name: FormalName):
            nonlocal param, future
            try:
                data = await aio.wait_for(future, timeout=param.lifetime / 1000.0)
            except aio.TimeoutError:
                self.pending_list = [ele for ele in self.pending_list if ele[0] is not future]
                raise InterestTimeout(final_name)
            return data

        self.pending_list.append((future, param.lifetime, param.can_be_prefix, param.must_be_fresh))
        return wait_for_data

    def nack_interest(self, nack_reason: int):
        for future, _, _, _ in self.pending_list:
            future.set_exception(InterestNack(nack_reason))
        self.pending_list = []
