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
import base64
from ...encoding import Name
from ...app_support.security_v2 import sign_req
from .utils import resolve_keychain, infer_obj_name


def add_parser(subparsers):
    parser = subparsers.add_parser('Get-SignReq', aliases=['sign-req', 'get-signreq', 'gsr'])
    parser.add_argument('obj', metavar='OBJECT', nargs='?', default='',
                        help='identity or key name')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    obj = args.obj
    id_name = []
    key_name = []

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
        return -2

    try:
        if key_name:
            key = iden[key_name]
        else:
            key = iden.default_key()
    except KeyError as e:
        print('Requested key does not exist.')
        print(f'KeyError: {e}')
        return -2

    _, data = sign_req(key.name, key.key_bits, kc.get_signer({'key': key.name}))
    text = base64.standard_b64encode(bytes(data)).decode()
    cnt = (len(text) + 63) // 64
    for i in range(cnt):
        print(text[i * 64:(i + 1) * 64])
