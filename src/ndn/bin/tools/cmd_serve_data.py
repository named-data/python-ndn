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
from ...encoding import Name, MetaInfo
from ...appv2 import NDNApp
from ...security import KeychainDigest


def add_parser(subparsers):
    parser = subparsers.add_parser('Serve-Data', aliases=['poke', 'sd', 'serve-data'])
    parser.add_argument('-f', '--freshness', metavar='FRESHNESS', default=60000, type=int,
                        help='the freshness period of the Data packet')
    parser.add_argument('-o', '--output', metavar='FILE',
                        help='write the AppParam into a file')
    # More to be added
    parser.add_argument('name', metavar='NAME',
                        help='the name of the Data packet')
    parser.add_argument('file', metavar='FILE', nargs='?', default='-',
                        help="file containing the content of the Data, '-' for stdin (default)")
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    fresh = args.freshness
    try:
        name = Name.from_str(args.name)
    except (ValueError, IndexError):
        print(f'Invalid name: {args.name}')
        return -1

    try:
        if args.file == '-':
            text = sys.stdin.read().encode()
        else:
            with open(os.path.expandvars(args.file), 'rb') as f:
                text = f.read()
    except (ValueError, OSError, IndexError):
        print('Unable to read the input file')
        return -2

    app = NDNApp()
    keychain = KeychainDigest()

    @app.route(name)
    def on_interest(int_name, app_param, reply, context):
        print(f'>> I: {Name.to_str(int_name)}, {context["int_param"]}')
        if app_param:
            print(f'AppParam: (size: {len(bytes(app_param))})')
            if args.output:
                if args.output == '-':
                    print(bytes(app_param).decode())
                else:
                    with open(os.path.expandvars(args.output), 'wb') as f:
                        f.write(bytes(app_param))
        content = text
        reply(app.make_data(name, signer=keychain.get_signer({}), content=content, freshness_period=fresh))
        print(f'<< D: {Name.to_str(name)}')
        print(MetaInfo(freshness_period=fresh))
        print(f'Content: (size: {len(content)})')
        print('')

    print(f'Start serving {Name.to_str(name)} ...')
    app.run_forever()
