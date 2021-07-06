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
import sys
import argparse
from ...platform import Platform
from ...security import KeychainSqlite3
from ...client_conf import default_keychain


def resolve_keychain(args: argparse.Namespace) -> KeychainSqlite3:
    tpm = args.tpm
    tpm_path = args.tpm_path
    base_dir = args.path
    platform = Platform()
    if not tpm:
        tpm = platform.default_tpm_schema()
    if tpm == 'tpm-osxkeychain' and sys.platform != 'darwin':
        print(f'ERROR: {tpm} only works on MacOS.')
        exit(-2)
    if tpm == 'tpm-cng' and sys.platform != 'win32':
        print(f'ERROR: {tpm} only works on Windows 10/11 with a TPM chip.')
        exit(-2)
    if not base_dir:
        for d in platform.default_pib_paths():
            if os.path.exists(d):
                base_dir = d
                break
        if not base_dir:
            print(f'ERROR: Cannot find a PIB.')
            exit(-2)

    pib_path = os.path.join(base_dir, 'pib.db')
    if not os.path.exists(pib_path):
        print(f'ERROR: Specified or default PIB database file {pib_path} does not exist.')
        exit(-2)

    if not tpm_path:
        if tpm == 'tpm-file':
            tpm_path = os.path.join(base_dir, 'ndnsec-key-file')
        else:
            tpm_path = ''

    return default_keychain(f'pib-sqlite3:{base_dir}', f'{tpm}:{tpm_path}')
