from typing import Optional, Callable, Any, Coroutine, Dict
from .encoding import FormalName, MetaInfo, BinaryStr, InterestParam, Signer, SignaturePtrs


Route = Callable[[FormalName, InterestParam, Optional[BinaryStr]], None]
Validator = Callable[[FormalName, SignaturePtrs], Coroutine[Any, None, bool]]
KeyChain = Callable[[Dict[str, Any]], Signer]


class NetworkError(Exception):
    pass


class InterestTimeout(Exception):
    pass


class InterestCanceled(Exception):
    pass


class InterestNack(Exception):
    reason: int

    def __init__(self, reason: int):
        self.reason = reason


class ValidationFailure(Exception):
    name: FormalName
    meta_info: MetaInfo
    content: Optional[BinaryStr]

    def __init__(self, name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr]):
        self.name = name
        self.meta_info = meta_info
        self.content = content
