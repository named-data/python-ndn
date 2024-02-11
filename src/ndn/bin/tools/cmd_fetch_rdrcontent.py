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
from ...appv2 import NDNApp, pass_all
# from ...security import KeychainDigest
from ...types import InterestTimeout, InterestNack, InterestCanceled, ValidationFailure


METADATA_COMPONENT = Component.from_str('32=metadata')


def add_parser(subparsers):
    parser = subparsers.add_parser('Fetch-RdrContent', aliases=['catchunks', 'frc', 'fetch-rdrcontent'])
    parser.add_argument('-o', '--output', metavar='FILE',
                        help="write the AppParam into a file. '-' for stdout")
    parser.add_argument('-l', '--lifetime', metavar='LIFETIME', default=4000, type=int,
                        help='set InterestLifetime, in milliseconds')
    parser.add_argument('-f', '--fresh', action='store_true',
                        help='set MustBeFresh')
    parser.add_argument('-r', '--retries', metavar='RETRIES', default=15, type=int,
                        help="maximum number of retries in case of Nack or timeout (-1 = no limit)")
    parser.add_argument('-p', '--pipeline-type', metavar='PIPELINE', default='fixed',
                        help="reserved")
    parser.add_argument('name', metavar='NAME',
                        help='name prefix of the desired RDR content. A specific version number can be provided.')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    lifetime = args.lifetime
    try:
        name = Name.from_str(args.name)
    except (ValueError, IndexError):
        print(f'Invalid name: {args.name}')
        return -1
    retries = args.retries
    if retries <= 0:
        retries = sys.maxsize

    if Component.get_type(name[-1]) == Component.TYPE_VERSION and len(name) >= 2:
        if name[-2] == METADATA_COMPONENT:
            # Given metadata version
            meta_name = name
            data_name = None
            name = name[:-2]
        else:
            # Given data version
            data_name = name
            name = name[:-1]
            meta_name = name
    else:
        meta_name = name
        data_name = None
    name_len = len(name)

    app = NDNApp()
    # keychain = KeychainDigest()

    async def after_start():
        nonlocal data_name
        try:
            if data_name is None:
                data_name = await fetch_metadata(app, retries, meta_name, name_len, args.fresh, lifetime)
            content, cnt = await fetch_content(app, retries, data_name, args.fresh, lifetime)
            print(f'Segment Count: {cnt}  Content size: {len(content)}')
            if args.output:
                if args.output == '-':
                    print(content.decode())
                else:
                    with open(os.path.expandvars(args.output), 'wb') as f:
                        f.write(content)
        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print('Timeout')
        except InterestCanceled:
            print('Local forwarder disconnected')
        except ValidationFailure:
            print('Data failed to validate')
        except (ValueError, IndexError):
            print('Decoding error')
        except OSError as e:
            print(f'OSError: {e}')
        finally:
            app.shutdown()

    app.run_forever(after_start())


async def retry(app: NDNApp, retry_times, name, can_be_prefix, must_be_fresh, timeout):
    trial_times = 0
    while True:
        future = app.express(name, validator=pass_all, can_be_prefix=can_be_prefix,
                             must_be_fresh=must_be_fresh, lifetime=timeout)
        try:
            return await future
        except (InterestTimeout, InterestNack):
            trial_times += 1
            if trial_times >= retry_times:
                raise


async def fetch_metadata(app: NDNApp, retry_times, meta_name, _name_len, fresh, timeout):
    _, encoded_data_name, _ = await retry(app, retry_times, meta_name, True, fresh, timeout)
    try:
        data_name = Name.from_bytes(encoded_data_name)
    except (ValueError, IndexError):
        print(f'Unable to decode data name from metadata packet: {bytes(encoded_data_name).hex()}')
        raise
    return data_name


async def fetch_content(app: NDNApp, retry_times, data_name, fresh, timeout):
    i = 0
    ret = []
    while True:
        seg_component = Component.from_segment(i)
        _, cur, context = await retry(app, retry_times, data_name + [seg_component], False, fresh, timeout)
        ret.append(cur)
        meta = context['meta_info']
        final = meta.final_block_id
        if final is None or final == seg_component:
            break
        i += 1
    return b''.join(ret), i + 1
