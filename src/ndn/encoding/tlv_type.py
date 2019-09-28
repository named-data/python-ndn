from typing import Union, List


BinaryStr = Union[bytes, bytearray, memoryview]
VarBinaryStr = Union[bytearray, memoryview]
FormalName = List[BinaryStr]
NonStrictName = Union[List[Union[BinaryStr, str]], str, BinaryStr]
