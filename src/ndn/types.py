# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 Xinyu Ma
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
