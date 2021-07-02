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
import os
import ctypes as c
from .general import Platform


class Cng:
    __instance = None

    def __new__(cls):
        if Cng.__instance is None:
            Cng.__instance = object.__new__(cls)
        return Cng.__instance

    def __init__(self):
        if len(self.__dict__) > 0:
            return
        self.bcrypt = c.windll.bcrypt
        self.ncrypt = c.windll.ncrypt

        # TODO: Finish Windows 10 CNG


class Win32(Platform):
    def client_conf_paths(self):
        return [os.path.expandvars(r'%LOCALAPPDATA%\ndn\client.conf'),
                os.path.expandvars(r'%USERPROFILE%\ndn\client.conf'),
                os.path.expandvars(r'%ALLUSERSPROFILE%\ndn\client.conf')]

    def default_transport(self):
        # Note: %TEMP% won't be redirected even when the executable is a MSIX/MicrosoftStore app
        return 'unix://' + os.path.expandvars(r'%TEMP%\ndn\nfd.sock')

    def default_pib_schema(self):
        return 'pib-sqlite3'

    def default_pib_paths(self):
        return [os.path.expandvars(r'%LOCALAPPDATA%\ndn'),
                os.path.expandvars(r'%USERPROFILE%\ndn')]

    def default_tpm_schema(self):
        return 'tpm-cng'

    def default_tpm_paths(self):
        return [os.path.expandvars(r'%LOCALAPPDATA%\ndn\ndnsec-key-file'),
                os.path.expandvars(r'%USERPROFILE%\ndn\ndnsec-key-file')]
