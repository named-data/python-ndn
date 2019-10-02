from typing import Optional
from .encoding import FormalName, MetaInfo, BinaryStr


class NetworkError(Exception):
    pass


class InterestTimeout(Exception):
    pass


class InterestNack(Exception):
    reason: int

    def __init__(self, reason: int):
        self.reason = reason


class InvalidDataError(Exception):
    name: FormalName
    meta_info: MetaInfo
    content: Optional[BinaryStr]

    def __init__(self, name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr]):
        self.name = name
        self.meta_info = meta_info
        self.content = content
