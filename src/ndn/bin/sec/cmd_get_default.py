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
    parser = subparsers.add_parser('Get-Default', aliases=['gd', 'get-default'])
    parser.add_argument('-k', '--key', dest='verbose', action='store_const', const=1, default=0,
                        help='show default key, instead of identity')
    parser.add_argument('-c', '--cert', dest='verbose', action='store_const', const=2, default=0,
                        help='show default certificate, instead of identity')
    parser.add_argument('obj', metavar='OBJECT', nargs='?', default='',
                        help='target identity or key')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    verbose = args.verbose
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
        return -1
    if verbose <= 0:
        print(Name.to_str(iden.name))
        return 0

    try:
        if key_name:
            key = iden[key_name]
        else:
            key = iden.default_key()
    except KeyError as e:
        print('Requested key does not exist.')
        print(f'KeyError: {e}')
        return -1
    if verbose == 1:
        print(Name.to_str(key.name))
        return 0

    try:
        if cert_name:
            cert = key[cert_name]
        else:
            cert = key.default_cert()
    except KeyError as e:
        print('Requested certificate does not exist.')
        print(f'KeyError: {e}')
        return -1
    print(Name.to_str(cert.name))
    return 0
