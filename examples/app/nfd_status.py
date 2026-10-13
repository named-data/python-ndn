# -----------------------------------------------------------------------------
# Copyright (C) 2019-2026 The python-ndn authors
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
import asyncio as aio
import dataclasses as dc
import logging
import time

from ndn import app, types
from ndn.app_support.nfd_mgmt import GeneralStatus
from ndn.encoding.tlv_model import tlv_parse


async def fetch_status(ndn_app: app.NDNApp) -> GeneralStatus:
    _, content, _ = await ndn_app.express(
        '/localhost/nfd/status/general',
        validator=app.pass_all,
        must_be_fresh=True,
        can_be_prefix=True,
        lifetime=6000,
    )
    if content is None:
        raise ValueError('NFD status response has no Content')
    return tlv_parse(GeneralStatus, content, ignore_critical=True)


def print_status(status: GeneralStatus):
    for field in dc.fields(status):
        print(f'{field.name}: {getattr(status, field.name)}')


def main():
    parser = argparse.ArgumentParser(
        description='Retrieve NFD general status.',
    )
    parser.add_argument(
        '--interval',
        type=float,
        default=1.0,
        help='polling and reconnect interval in seconds (default: 1)',
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='retrieve once instead of polling',
    )
    args = parser.parse_args()
    if args.interval <= 0:
        parser.error('--interval must be positive')

    logging.basicConfig(
        format='[{asctime}]{levelname}:{message}',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO,
        style='{',
    )

    async def poll(ndn_app):
        while True:
            while True:
                try:
                    print_status(await fetch_status(ndn_app))
                    break
                except types.InterestNack as exc:
                    print(f'Nacked with reason={exc.reason}')
                except types.InterestTimeout:
                    print('Timeout')
                except types.ValidationFailure:
                    print('Data failed to validate')
                except (types.InterestCanceled, types.NetworkError):
                    return
                await aio.sleep(args.interval)

            if args.once:
                ndn_app.shutdown()
                return
            print()
            await aio.sleep(args.interval)

    while True:
        ndn_app = app.NDNApp()
        poll_task = poll(ndn_app)
        should_reconnect = True
        try:
            should_reconnect = aio.run(ndn_app.main_loop(after_start=poll_task))
        except (FileNotFoundError, ConnectionError, OSError):
            poll_task.close()
        except KeyboardInterrupt:
            poll_task.close()
            break
        if args.once or not should_reconnect:
            break
        print('Disconnected; reconnecting ...')
        time.sleep(args.interval)


if __name__ == '__main__':
    main()
