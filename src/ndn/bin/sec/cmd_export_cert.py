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
from .utils import resolve_keychain, get_default_cert


def add_parser(subparsers):
    parser = subparsers.add_parser('Export-Cert', aliases=['export', 'ec', 'export-cert'])
    parser.add_argument('obj', metavar='OBJECT', nargs='?', default='',
                        help='name of the identity/key/certificate to export.')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    cert = get_default_cert(kc, args)
    if cert is None:
        return -2

    text = base64.standard_b64encode(bytes(cert.data)).decode()
    cnt = (len(text) + 63) // 64
    for i in range(cnt):
        print(text[i * 64:(i + 1) * 64])
