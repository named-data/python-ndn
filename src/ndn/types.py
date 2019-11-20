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
r"""An OnInterest callback function for a route."""

Validator = Callable[[FormalName, SignaturePtrs], Coroutine[Any, None, bool]]
r"""A validator used to validate an Interest or Data packet."""


class NetworkError(Exception):
    """
    Raised when trying to send a packet before connecting to NFD.
    """
    pass


class InterestTimeout(Exception):
    """
    Raised when an Interest times out.
    """
    pass


class InterestCanceled(Exception):
    """
    Raised when an Interest is cancelled due to the loss of connection to NFD.
    """
    pass


class InterestNack(Exception):
    """
    Raised when receiving a NetworkNack.

    :ivar reason: reason for Nack.
    :vartype reason: int
    """
    reason: int

    def __init__(self, reason: int):
        self.reason = reason


class ValidationFailure(Exception):
    """
    Raised when failing to validate a Data packet.

    :ivar name: the Name of Data.
    :vartype name: :any:`FormalName`
    :ivar meta_info: the MetaInfo.
    :vartype meta_info: :any:`MetaInfo`
    :ivar content: the Content of Data.
    :vartype content: Optional[:any:`BinaryStr`]
    """
    name: FormalName
    meta_info: MetaInfo
    content: Optional[BinaryStr]

    def __init__(self, name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr]):
        self.name = name
        self.meta_info = meta_info
        self.content = content
