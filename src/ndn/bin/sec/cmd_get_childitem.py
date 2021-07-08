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
from base64 import standard_b64encode
from ...encoding import Name, SignatureType
from ...app_support.security_v2 import parse_certificate
from .utils import resolve_keychain


def add_parser(subparsers):
    parser = subparsers.add_parser('Get-ChildItem', aliases=['list', 'ls', 'gci', 'get-childitem'])
    parser.add_argument('-k', '--key', dest='verbose', action='store_const', const=1, default=0,
                        help='list all keys associated with each identity')
    parser.add_argument('-c', '--cert', dest='verbose', action='store_const', const=2, default=0,
                        help='list all certificates associated with each key')
    parser.add_argument('-v', '--verbose', action='count', default=0,
                        help='verbose mode, can be repeated for increased verbosity: '
                             '-v is equivalent to -k, -vv is equivalent to -c, -vvv '
                             'shows detailed information for each certificate')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    kc = resolve_keychain(args)
    verbose = args.verbose

    for iden_name in kc:
        iden = kc[iden_name]
        is_default_id = '*' if iden.is_default else ' '
        print(f'{is_default_id} {Name.to_str(iden_name)}')
        if verbose >= 1:
            for key_name in iden:
                key = iden[key_name]
                is_default_key = '*' if key.is_default else ' '
                print(f'  +->{is_default_key} {Name.to_str(key_name)}')
                if verbose >= 2:
                    for cert_name in key:
                        cert = key[cert_name]
                        is_default_cert = '*' if cert.is_default else ' '
                        print(f'       +->{is_default_cert} {Name.to_str(cert_name)}')
                        if verbose >= 3:
                            print_cert(cert)
            print()
    print()


def print_cert(cert):
    try:
        cert_val = parse_certificate(cert.data)
    except (ValueError, IndexError):
        print('            Unable to parse certificate')
        return
    print('            Certificate name:')
    print('              ' + Name.to_str(cert.name))
    if cert_val.signature_info and cert_val.signature_info.validity_period:
        print('            Validity:')
        print(f'              NotBefore: {bytes(cert_val.signature_info.validity_period.not_before).decode()}')
        print(f'              NotAfter:  {bytes(cert_val.signature_info.validity_period.not_after).decode()}')
    if cert_val.content:
        print('            Public key bits:')
        text = standard_b64encode(bytes(cert_val.content)).decode()
        cnt = (len(text) + 63) // 64
        for i in range(cnt):
            print(f'              {text[i*64:(i+1)*64]}')
    if cert_val.signature_info:
        print('            Signature Information:')
        sig_type_dict = {
            SignatureType.NOT_SIGNED: 'Not Signed',
            SignatureType.DIGEST_SHA256: 'DigestSha256',
            SignatureType.SHA256_WITH_RSA: 'SignatureSha256WithRsa',
            SignatureType.SHA256_WITH_ECDSA: 'SignatureSha256WithEcdsa',
            SignatureType.HMAC_WITH_SHA256: 'SignatureHmacWithSha256',
        }
        sig_type = sig_type_dict.get(cert_val.signature_info.signature_type, 'Unknown')
        print(f'              Signature Type: {sig_type}')
        if cert_val.signature_info.key_locator and cert_val.signature_info.key_locator.name:
            print(f'              Key Locator: {Name.to_str(cert_val.signature_info.key_locator.name)}')
