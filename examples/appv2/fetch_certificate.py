# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
import sys
import logging
from ndn import appv2, types
from ndn import encoding as enc
from ndn.app_support import security_v2 as secv2


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


if len(sys.argv) < 2:
    logging.fatal('Please input a KEY or CERT name')
    exit(0)

app = appv2.NDNApp()


async def main():
    try:
        name = enc.Name.from_str(sys.argv[1])
        can_be_prefix = not (len(name) > 4 and name[-4] == secv2.KEY_COMPONENT)
        print(f'Sending Interest {enc.Name.to_str(name)}, '
              f'{enc.InterestParam(must_be_fresh=True, can_be_prefix=can_be_prefix, lifetime=6000)}')
        # TODO: Write a better validator
        data_name, content, pkt_context = await app.express(
            name, validator=appv2.pass_all,
            must_be_fresh=True, can_be_prefix=can_be_prefix, lifetime=6000)

        print(f'Received Data Name: {enc.Name.to_str(data_name)}')
        print(pkt_context['meta_info'])
        print(bytes(content) if content else None)
    except types.InterestNack as e:
        print(f'Nacked with reason={e.reason}')
    except types.InterestTimeout:
        print(f'Timeout')
    except types.InterestCanceled:
        print(f'Canceled')
    except types.ValidationFailure:
        print(f'Data failed to validate')
    finally:
        app.shutdown()


if __name__ == '__main__':
    app.run_forever(after_start=main())
