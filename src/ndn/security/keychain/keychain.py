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
