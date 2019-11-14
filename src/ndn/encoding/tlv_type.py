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
r"""A binary string is any of :class:`bytes`, :class:`bytearray`, :class:`memoryview`."""

VarBinaryStr = Union[bytearray, memoryview]
r"""A variant binary string is a :class:`bytearray` or a non-readonly :class:`memoryview`."""

FormalName = List[BinaryStr]
r"""A FormalName is a list of encoded Components."""

NonStrictName = Union[Iterable[Union[BinaryStr, str]], str, BinaryStr]
r"""
A NonStrictName is any of below:

- A URI string.
- A list or iterator of Components, in the form of either encoded TLV or URI string.
- An encoded Name of type :class:`bytes`, :class:`bytearray` or :class:`memoryview`.

See also :ref:`label-different-names`
"""


def is_binary_str(var):
    r"""
    Check whether var is of type BinaryStr.

    :param var: The variable to check.
    :return: ``True`` if var is a :any:`BinaryStr`.
    """
    return isinstance(var, bytes) or isinstance(var, bytearray) or isinstance(var, memoryview)
