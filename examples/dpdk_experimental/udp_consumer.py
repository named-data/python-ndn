# -----------------------------------------------------------------------------
# Copyright (C) 2019-2023 The python-ndn authors
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
import sys
from ndn import utils, appv2, types
from ndn import encoding as enc
from ndn.transport.ndn_dpdk import NdnDpdkUdpFace, DpdkRegisterer


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


# Usage example: python udp_consumer.py http://localhost:3030 172.17.0.1 9001 172.17.0.2 9001
if len(sys.argv) < 6:
    print('Insufficient argument')
    sys.exit(-1)

gpl_url = sys.argv[1]
self_addr = sys.argv[2]
self_port = int(sys.argv[3])
dpdk_addr = sys.argv[4]
dpdk_port = int(sys.argv[5])

face = NdnDpdkUdpFace(gpl_url, self_addr, self_port, dpdk_addr, dpdk_port)
registerer = DpdkRegisterer(face)

app = appv2.NDNApp(face=face, registerer=registerer)
keychain = app.default_keychain()


async def main():
    try:
        timestamp = utils.timestamp()
        name = enc.Name.from_str('/example/testApp/randomData') + [enc.Component.from_timestamp(timestamp)]
        print(f'Sending Interest {enc.Name.to_str(name)}, {enc.InterestParam(must_be_fresh=True, lifetime=6000)}')
        # TODO: Write a better validator
        data_name, content, pkt_context = await app.express(
            name, validator=appv2.pass_all,
            must_be_fresh=True, can_be_prefix=False, lifetime=6000)

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
