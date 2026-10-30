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
import logging

from ndn import app as ndn_app, encoding as enc
from ndn.security import DigestSha256Signer, sha256_digest_checker


logging.basicConfig(
    format='[{asctime}]{levelname}:{message}',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO,
    style='{',
)


app = ndn_app.NDNApp()
data_signer = DigestSha256Signer()


@app.route('/example/rpc', validator=sha256_digest_checker)
def on_interest(
    name: enc.FormalName,
    app_param: enc.BinaryStr | None,
    reply: ndn_app.ReplyFunc,
    context: ndn_app.PktContext,
):
    print(f'>> I: {enc.Name.to_str(name)}, {context["int_param"]}')
    if app_param is None:
        print('<< No ApplicationParameters, dropped')
        return

    try:
        result = sum(int(value) for value in bytes(app_param).split())
        content = str(result).encode()
    except ValueError:
        content = b'ERROR: parameters must be integers'

    packet = app.make_data(
        name,
        content=content,
        signer=data_signer,
        freshness_period=500,
    )
    if reply(packet):
        print(f'<< D: {enc.Name.to_str(name)}')
        print(f'Content: {content!r}')


if __name__ == '__main__':
    app.run_forever()
