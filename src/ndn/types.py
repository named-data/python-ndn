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
from enum import Enum
from typing import Optional, Callable, Any, Coroutine
from .encoding import FormalName, MetaInfo, BinaryStr, InterestParam, SignaturePtrs


Route = Callable[[FormalName, InterestParam, Optional[BinaryStr]], None]
r"""An OnInterest callback function for a route."""

Validator = Callable[[FormalName, SignaturePtrs], Coroutine[Any, None, bool]]
r"""A validator used to validate an Interest or Data packet."""

# For internal use. = (FormalName, MetaInfo, Content, SigPtrs, RawPacket)
DataTuple = tuple[FormalName, MetaInfo, Optional[BinaryStr], SignaturePtrs, BinaryStr]


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

    .. note::
        A very large packet may cause NFD shutting down the connection.
        More specifically,

        - The face is shutdown.
        - All pending Interests are cancelled with this exception.
        - ``App.run_forever()`` returns ``True``.
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


class ValidResult(Enum):
    """
    Validation result returned by a validator.
    Most of them are designed for the union checker, which chains multiple checkers in order.
    For NDNApp (v2), only PASS and ALLOW_BYPASS are considered as True.
    """

    FAIL = -2
    r"""Negative. The validation fails and the packet should be discarded. Abort."""

    TIMEOUT = -1
    r"""The validation process exceeds the Interest deadline. Abort."""

    SILENCE = 0
    r"""The validator does not handle this type of packet and thus cannot decide. Continue."""

    PASS = 1
    r"""Affirmative. Passes the current check. Continue."""

    ALLOW_BYPASS = 2
    r"""The validator allows bypassing all following checkers. Succeed immediately."""


class ValidationFailure(Exception):
    """
    Raised when failing to validate a Data packet.

    :ivar name: the Name of Data.
    :vartype name: :any:`FormalName`
    :ivar meta_info: the MetaInfo.
    :vartype meta_info: :any:`MetaInfo`
    :ivar content: the Content of Data.
    :vartype content: Optional[:any:`BinaryStr`]
    :ivar sig_ptrs: the signature pointers of Data
    :vartype sig_ptrs: :any:`SignaturePtrs`
    :ivar result: the reason of failure.
    :vartype result: :any:`ValidResult`
    """
    name: FormalName
    meta_info: MetaInfo
    content: Optional[BinaryStr]
    sig_ptrs: SignaturePtrs
    result: ValidResult

    def __init__(self, name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr],
                 sig_ptrs: SignaturePtrs, result: ValidResult = ValidResult.FAIL):
        self.name = name
        self.meta_info = meta_info
        self.content = content
        self.sig_ptrs = sig_ptrs
        self.result = result
