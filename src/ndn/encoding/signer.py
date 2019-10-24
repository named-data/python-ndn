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
import abc
from typing import List
from .tlv_type import VarBinaryStr


__all__ = ['Signer']


class Signer(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def write_signature_info(self, signature_info):
        pass

    @abc.abstractmethod
    def get_signature_value_size(self):
        pass

    @abc.abstractmethod
    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]):
        pass
