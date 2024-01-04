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
import asyncio as aio
from .general import Platform


class Linux(Platform):
    def client_conf_paths(self):
        return [os.path.expanduser('~/.ndn/client.conf'),
                '/usr/local/etc/ndn/client.conf',
                '/opt/local/etc/ndn/client.conf',
                '/etc/ndn/client.conf']

    def default_transport(self):
        if not os.path.exists('/run/nfd/nfd.sock') and os.path.exists('/run/nfd.sock'):
            # Try to be compatible to old NFD
            return 'unix:///run/nfd.sock'
        return 'unix:///run/nfd/nfd.sock'

    def default_pib_scheme(self):
        return 'pib-sqlite3'

    def default_pib_paths(self):
        return [os.path.expanduser(r'~/.ndn')]

    def default_tpm_scheme(self):
        return 'tpm-file'

    def default_tpm_paths(self):
        return [os.path.expanduser(r'~/.ndn/ndnsec-key-file')]

    async def open_unix_connection(self, path=None):
        return await aio.open_unix_connection(path)
