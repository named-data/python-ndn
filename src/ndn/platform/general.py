# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
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
import sys
from typing import List

__all__ = ['Platform']


class Platform(abc.ABC):
    _instance = None

    def __new__(cls):
        if Platform._instance is None:
            if sys.platform == 'darwin':
                from .osx import Darwin
                target_class = Darwin
            elif sys.platform == 'linux':
                from .linux import Linux
                target_class = Linux
            elif sys.platform == 'win32':
                from .windows import Win32
                target_class = Win32
            else:
                raise ValueError(f'Unsupported platform: {sys.platform}')
            Platform._instance = object.__new__(target_class)
        return Platform._instance

    @abc.abstractmethod
    def client_conf_paths(self) -> List[str]:
        pass

    @abc.abstractmethod
    def default_transport(self) -> str:
        pass

    @abc.abstractmethod
    def default_pib_scheme(self) -> str:
        pass

    @abc.abstractmethod
    def default_pib_paths(self) -> List[str]:
        pass

    @abc.abstractmethod
    def default_tpm_scheme(self) -> str:
        pass

    @abc.abstractmethod
    def default_tpm_paths(self) -> List[str]:
        pass

    @abc.abstractmethod
    async def open_unix_connection(self, path=None):
        pass
