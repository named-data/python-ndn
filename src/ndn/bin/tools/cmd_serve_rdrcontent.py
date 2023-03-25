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
from ...encoding import Name, Component
from ...appv2 import NDNApp
from ...security import KeychainDigest
from ...utils import timestamp


METADATA_COMPONENT = Component.from_str('32=metadata')


def add_parser(subparsers):
    parser = subparsers.add_parser('Serve-RdrContent', aliases=['putchunks', 'src', 'serve-rdrcontent'])
    parser.add_argument('-f', '--freshness', metavar='FRESHNESS', default=60000, type=int,
                        help='the freshness period of the Data packet')
    parser.add_argument('-s', '--size', metavar='SIZE', default=8000, type=int,
                        help='maximum chunk size, in bytes')
    # More to be added
    parser.add_argument('name', metavar='NAME',
                        help='the name of the Data packet')
    parser.add_argument('file', metavar='FILE', nargs='?', default='-',
                        help="file containing the content of the Data, '-' for stdin (default)")
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    fresh = args.freshness
    size = args.size
    try:
        name = Name.from_str(args.name)
    except (ValueError, IndexError):
        print(f'Invalid name: {args.name}')
        return -1
    name_len = len(name)
    version = Component.from_version(timestamp())
    meta_name = name + [METADATA_COMPONENT, version, Component.from_segment(0)]
    data_name = name + [version]

    # This does not work for large file
    try:
        if args.file == '-':
            data = sys.stdin.read().encode()
        else:
            with open(os.path.expandvars(args.file), 'rb') as f:
                data = f.read()
    except (ValueError, OSError, IndexError):
        print('Unable to read the input file')
        return -2

    app = NDNApp()
    keychain = KeychainDigest()
    seg_cnt = (len(data) + size - 1) // size
    packets = [app.make_data(data_name + [Component.from_segment(i)],
                             data[i * size:(i + 1) * size],
                             signer=keychain.get_signer({}),
                             freshness_period=fresh,
                             final_block_id=Component.from_segment(seg_cnt - 1))
               for i in range(seg_cnt)]
    print(f'Created {seg_cnt} chunks under name prefix {Name.to_str(data_name)}')

    meta_packet = app.make_data(meta_name, Name.to_bytes(data_name),
                                signer=keychain.get_signer({}),
                                freshness_period=fresh, final_block_id=Component.from_segment(0))
    print(f'Created metadata packet under name {Name.to_str(meta_name)}')

    @app.route(name)
    def on_interest(int_name, _app_param, reply, _context):
        if len(int_name) == name_len or int_name[name_len] == METADATA_COMPONENT:
            reply(meta_packet)
        elif int_name[name_len] == version:
            if Component.get_type(int_name[-1]) == Component.TYPE_SEGMENT:
                seg_no = Component.to_number(int_name[-1])
            else:
                seg_no = 0
            if seg_no < seg_cnt:
                reply(packets[seg_no])

    print(f'Start serving {Name.to_str(name)} ...')
    app.run_forever()
