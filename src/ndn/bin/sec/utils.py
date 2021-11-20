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
from typing import Tuple
from ...platform import Platform
from ...security import KeychainSqlite3
from ...client_conf import default_keychain
from ...app_support.security_v2 import KEY_COMPONENT
from ...encoding import Name, FormalName


KEY_KEYWORD = KEY_COMPONENT


def resolve_keychain(args: argparse.Namespace) -> KeychainSqlite3:
    tpm = args.tpm
    tpm_path = args.tpm_path
    base_dir = args.path
    platform = Platform()
    if not tpm:
        tpm = platform.default_tpm_scheme()
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
            print('ERROR: Cannot find a PIB.')
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


def infer_obj_name(obj_name: FormalName) -> Tuple[int, FormalName, FormalName, FormalName]:
    if len(obj_name) > 2 and obj_name[-2] == KEY_KEYWORD:
        v = 1
        id_name = obj_name[:-2]
        key_name = obj_name
        cert_name = []
    elif len(obj_name) > 4 and obj_name[-4] == KEY_KEYWORD:
        v = 2
        id_name = obj_name[:-4]
        key_name = obj_name[:-2]
        cert_name = obj_name
    else:
        v = 0
        id_name = obj_name
        key_name = []
        cert_name = []
    return v, id_name, key_name, cert_name


def get_default_cert(kc: KeychainSqlite3, args: argparse.Namespace):
    obj = args.obj
    id_name = []
    key_name = []
    cert_name = []

    if obj:
        obj_name = Name.from_str(obj)
        _, id_name, key_name, cert_name = infer_obj_name(obj_name)

    try:
        if id_name:
            iden = kc[id_name]
        else:
            iden = kc.default_identity()
    except KeyError as e:
        print('Requested identity does not exist.')
        print(f'KeyError: {e}')
        return None

    try:
        if key_name:
            key = iden[key_name]
        else:
            key = iden.default_key()
    except KeyError as e:
        print('Requested key does not exist.')
        print(f'KeyError: {e}')
        return None

    try:
        if cert_name:
            cert = key[cert_name]
        else:
            cert = key.default_cert()
    except KeyError as e:
        print('Requested certificate does not exist.')
        print(f'KeyError: {e}')
        return None

    return cert
