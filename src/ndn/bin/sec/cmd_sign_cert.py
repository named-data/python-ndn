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
import base64
import argparse
from datetime import datetime, timedelta, timezone
from ...encoding import Name
from ...app_support.security_v2 import parse_certificate, new_cert
from .utils import resolve_keychain, infer_obj_name


def add_parser(subparsers):
    parser = subparsers.add_parser('Sign-Cert', aliases=['cert-gen', 'sc', 'sign-cert'])
    parser.add_argument('-s', '--not-before', metavar='TIMESTAMP',
                        help="certificate validity start date/time in 19700101T000000 format (default: now)")
    parser.add_argument('-e', '--not-after', metavar='TIMESTAMP',
                        help="certificate validity end date/time in 19700101T000000 format (default: 365 days"
                             " after the -s timestamp)")
    parser.add_argument('-i', '--issuer-id', metavar='ISSUER', default='NA',
                        help="issuer's ID to be included in the issued certificate name (default: NA)")
    parser.add_argument('key_locator', metavar='KEY_LOCATOR',
                        help="signing identity/key or key locator certificate")
    parser.add_argument('file', metavar='FILE', nargs='?', default='-',
                        help="sign request file name, '-' for stdin (the default)")
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)

    if args.file == '-':
        text = sys.stdin.read()
    else:
        with open(os.path.expandvars(args.file), 'r') as f:
            text = f.read()
    try:
        sign_req_data = base64.standard_b64decode(text)
        sign_req = parse_certificate(sign_req_data)
        if not sign_req.name or not sign_req.content:
            raise ValueError()
        signee_key_name = sign_req.name[:-2]
    except (ValueError, IndexError):
        print('Malformed certificate')
        return -1
    # Note: Do we need to check the validity of sign_req?

    key_loc = Name.normalize(args.key_locator)
    v, id_name, key_name, cert_name = infer_obj_name(key_loc)
    try:
        if v == 0:
            signer = kc.get_signer({'identity': id_name})
        elif v == 1:
            signer = kc.get_signer({'key': key_name})
        else:
            signer = kc.get_signer({'cert': cert_name})
    except KeyError:
        if v == 0:
            print(f'Specified identity does not exist: {Name.to_str(id_name)}')
        elif v == 1:
            print(f'Specified key does not exist: {Name.to_str(key_name)}')
        else:
            print(f'Specified certificate does not exist: {Name.to_str(cert_name)}')
        return -2
    # Currently python-ndn does not support putting a certificate name into KeyLocator

    try:
        issuer = Name.from_str(args.issuer_id)
        if len(issuer) != 1:
            raise IndexError()
        issuer_id = issuer[0]
    except (ValueError, IndexError):
        print('Issue ID is not a single component')
        return -3

    if not args.not_before:
        not_before = datetime.now(timezone.utc)
    else:
        try:
            not_before = datetime.strptime(args.not_before, '%Y%m%dT%H%M%S')
        except ValueError:
            print(f'Not-before is not of valid format: {args.not_before}')
            return -4

    if not args.not_after:
        not_after = not_before + timedelta(days=365)
    else:
        try:
            not_after = datetime.strptime(args.not_after, '%Y%m%dT%H%M%S')
        except ValueError:
            print(f'Not-after is not of valid format: {args.not_after}')
            return -4

    try:
        _, cert = new_cert(signee_key_name, issuer_id, sign_req.content, signer, not_before, not_after)
    except (ValueError, IndexError):
        print('Failed to issue the certificate')
        return -5

    text = base64.standard_b64encode(bytes(cert)).decode()
    cnt = (len(text) + 63) // 64
    for i in range(cnt):
        print(text[i * 64:(i + 1) * 64])
