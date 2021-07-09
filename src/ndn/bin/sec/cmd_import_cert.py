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
import base64
import os
import sys
import argparse
from ...encoding import Name
from ...app_support.security_v2 import parse_certificate
from .utils import resolve_keychain


def add_parser(subparsers):
    parser = subparsers.add_parser('Import-Cert', aliases=['import', 'ic', 'import-cert'])
    parser.add_argument('file', metavar='FILE', nargs='?', default='-',
                        help="file name of the certificate to be imported, '-' for stdin")
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    if args.file == '-':
        text = sys.stdin.read()
    else:
        with open(os.path.expandvars(args.file), 'r') as f:
            text = f.read()

    try:
        cert_data = base64.standard_b64decode(text)
        cert = parse_certificate(cert_data)
    except (ValueError, IndexError):
        print('Malformed certificate')
        return -1

    cert_name = cert.name
    key_name = cert_name[:-2]
    id_name = cert_name[:-4]
    try:
        key = kc[id_name][key_name]
    except KeyError:
        print(f'Specified key {Name.to_str(key_name)} does not exist.')
        return -2
    try:
        _ = key[cert_name]
        print(f'Specified certificate {Name.to_str(cert_name)} already exists.')
        return -2
    except KeyError:
        pass
    kc.import_cert(key_name, cert_name, cert_data)
