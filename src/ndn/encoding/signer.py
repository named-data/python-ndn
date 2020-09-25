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
from typing import List
from .tlv_type import VarBinaryStr


__all__ = ['Signer']


class Signer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def write_signature_info(self, signature_info):
        """
        Fill in the fields of SignatureInfo.

        :param signature_info: a blank SignatureInfo object.
        """
        pass

    @abc.abstractmethod
    def get_signature_value_size(self) -> int:
        """
        Get the size of SignatureValue.
        If the size is variable, return the maximum possible value.

        :return: the size of SignatureValue.
        """
        pass

    @abc.abstractmethod
    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
        """
        Calculate the SignatureValue and write it into wire.
        The length of wire is exactly what :meth:`get_signature_value_size` returns.
        Basically this function should return the same value except for ECDSA.

        :param wire: the buffer to contain SignatureValue.
        :param contents: a list of memory blocks that needs to be covered.
        :return: the actual size of SignatureValue.
        """
        pass
