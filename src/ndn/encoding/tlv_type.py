from typing import Union, List, Iterable


__all__ = ['BinaryStr', 'VarBinaryStr', 'FormalName', 'NonStrictName', 'is_binary_str']


BinaryStr = Union[bytes, bytearray, memoryview]
VarBinaryStr = Union[bytearray, memoryview]
FormalName = List[BinaryStr]
NonStrictName = Union[Iterable[Union[BinaryStr, str]], str, BinaryStr]


def is_binary_str(var):
    return isinstance(var, bytes) or isinstance(var, bytearray) or isinstance(var, memoryview)
