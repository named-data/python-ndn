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
from ...encoding import Name, InterestParam
from ...appv2 import NDNApp, pass_all
# from ...security import KeychainDigest
from ...types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure


def add_parser(subparsers):
    parser = subparsers.add_parser('Fetch-Data', aliases=['peek', 'fd', 'fetch-data'])
    parser.add_argument('-o', '--output', metavar='FILE',
                        help="write the AppParam into a file. '-' for stdout")
    parser.add_argument('-l', '--lifetime', metavar='LIFETIME', default=4000, type=int,
                        help='set InterestLifetime, in milliseconds')
    parser.add_argument('-p', '--prefix', action='store_true',
                        help='set CanBePrefix')
    parser.add_argument('-f', '--fresh', action='store_true',
                        help='set MustBeFresh')
    parser.add_argument('-a', '--app-param', metavar='APP-PARAM',
                        help="set ApplicationParameters from a file, '-' for stdin")
    parser.add_argument('name', metavar='NAME',
                        help='name or name prefix of the desired Data packet')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    lifetime = args.lifetime
    try:
        name = Name.from_str(args.name)
    except (ValueError, IndexError):
        print(f'Invalid name: {args.name}')
        return -1

    try:
        if args.app_param:
            if args.app_param == '-':
                app_param = sys.stdin.read().encode()
            else:
                with open(os.path.expandvars(args.app_param), 'rb') as f:
                    app_param = f.read()
        else:
            app_param = None
    except (ValueError, OSError, IndexError):
        print('Unable to read the input file')
        return -2

    app = NDNApp()

    async def after_start():
        try:
            print(f'Sending Interest {Name.to_str(name)},'
                  f' {InterestParam(must_be_fresh=args.fresh, can_be_prefix=args.prefix, lifetime=lifetime)}')
            data_name, content, context = await app.express(
                name, validator=pass_all,
                must_be_fresh=args.fresh, can_be_prefix=args.prefix, lifetime=lifetime,
                app_param=app_param)
            meta_info = context['meta_info']

            print(f'Received Data Name: {Name.to_str(data_name)}')
            print(meta_info)
            if content:
                print(f'Content: (size {len(bytes(content))})')
                if args.output:
                    if args.output == '-':
                        print(bytes(content).decode())
                    else:
                        with open(os.path.expandvars(args.output), 'wb') as f:
                            f.write(bytes(content))
        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print('Timeout')
        except InterestCanceled:
            print('Local forwarder disconnected')
        except ValidationFailure:
            print('Data failed to validate')
        finally:
            app.shutdown()

    app.run_forever(after_start())
