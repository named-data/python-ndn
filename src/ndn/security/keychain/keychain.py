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
import collections
from typing import Dict, Any


class Keychain(collections.abc.Mapping):
    """
    The abstract Keychain class, derived from :class:`collections.abc.Mapping`.
    It behaves like an immutable dict from :any:`FormalName` to Identity.
    The implementation of Identity varies with concrete implementations.
    Generally, its methods should also accept :any:`NonStrictName` as inputs.
    This includes operators such as ``in`` and ``[]``.
    """
    # __getitem__ will be called extra times, but there is no need to optimize for performance
    @abc.abstractmethod
    def get_signer(self, sign_args: Dict[str, Any]):
        """
        Get a signer from sign_args.

        :param sign_args: the signing arguments provided by the application.
        :return: a signer.
        :rtype: :any:`Signer`
        """
        pass
