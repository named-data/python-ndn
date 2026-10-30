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
import logging

from ndn import app as ndn_app, encoding as enc, types, utils
from ndn.security import DigestSha256Signer


def main():
    parser = argparse.ArgumentParser(
        description='Add integers through an ApplicationParameters RPC.',
    )
    parser.add_argument('integers', nargs='+', type=int)
    args = parser.parse_args()

    logging.basicConfig(
        format='[{asctime}]{levelname}:{message}',
        datefmt='%Y-%m-%d %H:%M:%S',
        level=logging.INFO,
        style='{',
    )

    app = ndn_app.NDNApp()

    async def after_start():
        try:
            name = enc.Name.from_str('/example/rpc') + [
                enc.Component.from_timestamp(utils.timestamp()),
            ]
            app_param = ' '.join(
                str(value) for value in args.integers
            ).encode()
            print(
                f'Sending Interest {enc.Name.to_str(name)} '
                f'with ApplicationParameters {app_param!r}'
            )
            data_name, content, context = await app.express(
                name,
                validator=ndn_app.pass_all,
                app_param=app_param,
                signer=DigestSha256Signer(for_interest=True),
                must_be_fresh=True,
                can_be_prefix=False,
                lifetime=6000,
            )
            print(f'Received Data Name: {enc.Name.to_str(data_name)}')
            print(context['meta_info'])
            print(bytes(content).decode() if content is not None else None)
        except types.InterestNack as exc:
            print(f'Nacked with reason={exc.reason}')
        except types.InterestTimeout:
            print('Timeout')
        except types.InterestCanceled:
            print('Canceled')
        except types.ValidationFailure:
            print('Data failed to validate')
        finally:
            app.shutdown()

    app.run_forever(after_start=after_start())


if __name__ == '__main__':
    main()
