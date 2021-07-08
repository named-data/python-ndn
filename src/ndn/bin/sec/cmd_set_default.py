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
import argparse
from ...encoding import Name
from .utils import resolve_keychain, infer_obj_name


def add_parser(subparsers):
    parser = subparsers.add_parser('Set-Default', aliases=['sd', 'set-default'])
    parser.add_argument(dest='obj', metavar='OBJECT',
                        help='the identity/key/certificate name to set')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    obj_name = Name.from_str(args.obj)
    v, id_name, key_name, cert_name = infer_obj_name(obj_name)

    try:
        iden = kc[id_name]
    except KeyError as e:
        print('Requested identity does not exist.')
        print(f'KeyError: {e}')
        return -1
    if v <= 0:
        kc.set_default_identity(id_name)
        return 0

    try:
        key = iden[key_name]
    except KeyError as e:
        print('Requested key does not exist.')
        print(f'KeyError: {e}')
        return -1
    if v <= 1:
        iden.set_default_key(key_name)
        return 0

    try:
        _ = key[cert_name]
    except KeyError as e:
        print('Requested certificate does not exist.')
        print(f'KeyError: {e}')
        return -1
    key.set_default_cert(cert_name)
    return 0
