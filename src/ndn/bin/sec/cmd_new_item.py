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
    parser = subparsers.add_parser('New-Item', aliases=['key-gen', 'ni', 'new-item'])
    parser.add_argument('-t', '--type', metavar='TYPE', default='e', choices=['e', 'r'],
                        help="key type: 'r' for RSA, 'e' for ECDSA (default: e)")
    parser.add_argument('-k', '--keyid-type', metavar='KEYIDTYPE', default='r', choices=['h', 'r'],
                        help="key id type: 'h' for the SHA-256 of the public key, "
                             "'r' for a 64-bit random number (the default unless "
                             "a key name is specified for OBJECT)")
    parser.add_argument('obj', metavar='OBJECT', help='identity/key name')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    obj_name = Name.from_str(args.obj)
    _, id_name, key_name, cert_name = infer_obj_name(obj_name)

    # New identity
    try:
        iden = kc[id_name]
    except KeyError:
        iden = kc.new_identity(id_name)
        print(f'Created new identity: {Name.to_str(id_name)}')

    # New key
    if key_name:
        try:
            _ = iden[key_name]
            print(f'Specified key already exists: {Name.to_str(key_name)}')
            return -2
        except KeyError:
            key = None
    else:
        key = None
    if key is None:
        key_type = 'ec' if args.type == 'e' else 'rsa'
        if key_name:
            key = kc.new_key(id_name, key_type, key_id=key_name[-1])
        else:
            key_id_type = 'sha256' if args.keyid_type == 'h' else 'random'
            key = kc.new_key(id_name, key_type, key_id_type=key_id_type)
        key_name = key.name
        print(f'Created new key: {Name.to_str(key_name)}')
        print(f'With self-signed certificate: {Name.to_str(key.default_cert().name)}')
