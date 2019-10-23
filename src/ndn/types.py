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
from typing import Optional, Callable, Any, Coroutine
from .encoding import FormalName, MetaInfo, BinaryStr, InterestParam, SignaturePtrs


Route = Callable[[FormalName, InterestParam, Optional[BinaryStr]], None]
Validator = Callable[[FormalName, SignaturePtrs], Coroutine[Any, None, bool]]


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
