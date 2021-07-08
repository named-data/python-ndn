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
    parser = subparsers.add_parser('Remove-Item', aliases=['del', 'rm', 'ri', 'remove-item'])
    parser.add_argument('obj', metavar='OBJECT',
                        help='name of the identity/key/certificate to delete.')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    obj_name = Name.from_str(args.obj)
    v, id_name, key_name, cert_name = infer_obj_name(obj_name)

    if v <= 0:
        kc.del_identity(id_name)
        print(f'Deleted identity {Name.to_str(id_name)}')
    elif v == 1:
        kc.del_key(key_name)
        print(f'Deleted key {Name.to_str(key_name)}')
    else:
        kc.del_cert(cert_name)
        print(f'Deleted certificate {Name.to_str(cert_name)}')
