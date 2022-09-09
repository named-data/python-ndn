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
import logging
from ndn import utils, appv2, types
from ndn import encoding as enc


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


app = appv2.NDNApp()


async def express_int(name, fw_hint):
    try:
        if fw_hint is None:
            print(f'Sending Interest {enc.Name.to_str(name)}, {enc.InterestParam(must_be_fresh=True, lifetime=6000)}')
            data_name, content, pkt_context = await app.express(
                name, validator=appv2.pass_all,
                must_be_fresh=True, can_be_prefix=False, lifetime=6000)
        else:
            print(f'Sending Interest {enc.Name.to_str(name)}, '
                  f'{enc.InterestParam(must_be_fresh=True, lifetime=6000, forwarding_hint=[fw_hint])}')
            data_name, content, pkt_context = await app.express(
                name, validator=appv2.pass_all,
                must_be_fresh=True, can_be_prefix=False, lifetime=6000, forwarding_hint=[fw_hint])

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


async def main():
    timestamp = utils.timestamp()
    await express_int(enc.Name.from_str('/repo/command/random') + [enc.Component.from_timestamp(timestamp)],
                      None)
    await express_int(enc.Name.from_str('/example/testApp/randomData') + [enc.Component.from_timestamp(timestamp)],
                      enc.Name.from_str('/repo/files'))
    app.shutdown()


if __name__ == '__main__':
    app.run_forever(after_start=main())
