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
import abc
from typing import Optional
from ..encoding import SignaturePtrs, FormalName, InterestParam, BinaryStr
from ..encoding.signer import Signer
from ..types import Validator


class Policy:
    """
    Policy is an annotation attached to a node.
    """
    def __init__(self):
        self.node = None


class Cache(Policy, metaclass=abc.ABCMeta):
    """
    Cache policy determines how Data packets are stored.
    """
    @abc.abstractmethod
    async def search(self, match, name: FormalName, param: InterestParam):
        pass

    @abc.abstractmethod
    async def save(self, match, name: FormalName, packet: BinaryStr):
        pass


class InterestValidator(Policy, metaclass=abc.ABCMeta):
    """
    InterestValidator policy describes how to verify an Interest packet.
    """
    @abc.abstractmethod
    async def validate(self, match, sig_ptrs: SignaturePtrs) -> bool:
        pass


class DataValidator(Policy, metaclass=abc.ABCMeta):
    """
    DataValidator policy describes how to verify a Data packet.
    """
    @abc.abstractmethod
    def get_validator(self, match) -> Validator:
        pass


class Signing(Policy, metaclass=abc.ABCMeta):
    """
    Signing policy gives a signer used to sign a packet.
    When a user uses signing policy, he needs to specify whether its
    :class:`InterestSigning` or :class:`DataSigning`.
    """
    @abc.abstractmethod
    async def get_signer(self, match) -> Signer:
        pass


class InterestSigning(Signing, metaclass=abc.ABCMeta):
    """
    InterestSigning policy is a type used to indicate the Interest signer.
    Used as the type argument of set_policy.
    """
    pass


class DataSigning(Signing, metaclass=abc.ABCMeta):
    """
    DataSigning policy is a type used to indicate the Data signer.
    Used as the type argument of set_policy.
    """
    pass


class Encryption(Policy, metaclass=abc.ABCMeta):
    """
    Encryption policy encrypts and decrypts content.
    When a user uses encryption policy, he needs to specify whether its
    :class:`InterestEncryption` or :class:`DataEncryption`.
    """
    @abc.abstractmethod
    async def decrypt(self, match, content: BinaryStr) -> Optional[BinaryStr]:
        pass

    @abc.abstractmethod
    async def encrypt(self, match, content: BinaryStr) -> Optional[BinaryStr]:
        pass


class InterestEncryption(Encryption, metaclass=abc.ABCMeta):
    """
    InterestSigning policy is a type used to indicate the Interest encryption policy.
    Used as the type argument of set_policy.
    """
    pass


class DataEncryption(Encryption, metaclass=abc.ABCMeta):
    """
    DataEncryption policy is a type used to indicate the Data encryption policy.
    Used as the type argument of set_policy.
    """
    pass


class LocalOnly(Policy):
    """
    LocalOnly means the Data should be stored in the local storage.
    It prevents the node from sending Interest packets.
    """
    pass


class Register(Policy):
    """
    Register policy indicates the node should be registered as a prefix in the forwarder.
    """
    pass
