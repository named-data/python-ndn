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
import typing
import logging
import sys
from ndn import appv2
from ndn import encoding as enc
from ndn.transport.ndn_dpdk import NdnDpdkUdpFace, DpdkRegisterer


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')


# Usage example: python udp_producer.py http://localhost:3030 172.17.0.1 9000 172.17.0.2 9000
if len(sys.argv) < 6:
    print('Insufficient argument')
    sys.exit(-1)

gql_url = sys.argv[1]
self_addr = sys.argv[2]
self_port = int(sys.argv[3])
dpdk_addr = sys.argv[4]
dpdk_port = int(sys.argv[5])

face = NdnDpdkUdpFace(gql_url, self_addr, self_port, dpdk_addr, dpdk_port)
registerer = DpdkRegisterer(face)

app = appv2.NDNApp(face=face, registerer=registerer)
keychain = app.default_keychain()


@app.route('/example/testApp')
def on_interest(name: enc.FormalName, _app_param: typing.Optional[enc.BinaryStr],
                reply: appv2.ReplyFunc, context: appv2.PktContext):
    print(f'>> I: {enc.Name.to_str(name)}, {context["int_param"]}')
    content = "Hello, world!".encode()
    reply(app.make_data(name, content=content, signer=keychain.get_signer({}),
                        freshness_period=10000))
    print(f'<< D: {enc.Name.to_str(name)}')
    print(enc.MetaInfo(freshness_period=10000))
    print(f'Content: (size: {len(content)})')
    print('')


if __name__ == '__main__':
    app.run_forever()
