# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
    return isinstance(var, (bytes, bytearray, memoryview))
