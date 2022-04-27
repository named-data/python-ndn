# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
from collections.abc import Mapping
from typing import Any
from ...encoding import FormalName, BinaryStr


class AbstractCertificate(abc.ABC):
    @property
    @abc.abstractmethod
    def data(self) -> BinaryStr:
        """
        Get the binary data of the certificate,
        which is the wire form of the V2 certificate Data packet.

        :return: Certificate binary data.
        """
        pass

    @property
    @abc.abstractmethod
    def name(self) -> FormalName:
        """
        Get the Name of the certificate

        :return: Certificate Name.
        """
        pass

    @property
    @abc.abstractmethod
    def key(self) -> FormalName:
        """
        Get the Name of the Key

        :return: Key Name.
        """
        pass


class AbstractKey(Mapping[FormalName, AbstractCertificate]):
    @property
    @abc.abstractmethod
    def key_bits(self) -> BinaryStr:
        """
        Get the public key bits of the key.

        :return: Public key bits.
        """
        pass

    @property
    @abc.abstractmethod
    def name(self) -> FormalName:
        """
        Get the Name of the key

        :return: Key Name.
        """
        pass

    @property
    @abc.abstractmethod
    def identity(self) -> FormalName:
        """
        Get the Name of the Identity

        :return: Identity Name.
        """
        pass


class AbstractIdentity(Mapping[FormalName, AbstractKey]):
    @property
    @abc.abstractmethod
    def name(self) -> FormalName:
        """
        Get the Name of the identity

        :return: Identity Name.
        """
        pass


class Keychain(Mapping[FormalName, AbstractIdentity]):
    """
    The abstract Keychain class, derived from :class:`collections.abc.Mapping`.
    It behaves like an immutable dict from :any:`FormalName` to Identity.
    The implementation of Identity varies with concrete implementations.
    Generally, its methods should also accept :any:`NonStrictName` as inputs.
    This includes operators such as ``in`` and ``[]``.
    """
    # __getitem__ will be called extra times, but there is no need to optimize for performance
    @abc.abstractmethod
    def get_signer(self, sign_args: dict[str, Any]):
        """
        Get a signer from sign_args.

        :param sign_args: the signing arguments provided by the application.
        :return: a signer.
        :rtype: :any:`Signer`
        """
        pass
