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


def add_parser(subparsers):
    parser = subparsers.add_parser('Init-Pib', aliases=['init', 'init-pib'])
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    tpm = args.tpm
    tpm_path = args.tpm_path
    base_dir = args.path
    platform = Platform()
    if not tpm:
        tpm = platform.default_tpm_scheme()
    if tpm == 'tpm-osxkeychain' and sys.platform != 'darwin':
        print(f'ERROR: {tpm} only works on MacOS.')
        return -2
    if tpm == 'tpm-cng' and sys.platform != 'win32':
        print(f'ERROR: {tpm} only works on Windows 10/11 with a TPM chip.')
        return -2
    if not base_dir:
        base_dir = platform.default_pib_paths()[0]
    pib_path = os.path.join(base_dir, 'pib.db')
    if not tpm_path:
        if tpm == 'tpm-file':
            tpm_path = os.path.join(base_dir, 'ndnsec-key-file')
        else:
            tpm_path = ''
    print(f'Initializing PIB at {pib_path}, with tpm-locator={tpm}:{tpm_path}')
    ret = KeychainSqlite3.initialize(pib_path, tpm, tpm_path)
    if ret:
        print('Successfully created PIB. Before running any NDN application, '
              'Please make sure you have the correct client.conf and a default key.')
        return 0
    else:
        print('Failed to create PIB database.')
        return -1
