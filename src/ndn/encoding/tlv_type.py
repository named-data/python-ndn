# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
from typing import Union, List, Iterable


__all__ = ['BinaryStr', 'VarBinaryStr', 'FormalName', 'NonStrictName', 'is_binary_str']


BinaryStr = Union[bytes, bytearray, memoryview]
VarBinaryStr = Union[bytearray, memoryview]
FormalName = List[BinaryStr]
NonStrictName = Union[Iterable[Union[BinaryStr, str]], str, BinaryStr]


def is_binary_str(var):
    return isinstance(var, bytes) or isinstance(var, bytearray) or isinstance(var, memoryview)
