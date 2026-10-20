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
import os
import sys

from ndn import app as ndn_app, encoding as enc, types
from ndn.app_support.light_versec import (
    Checker,
    DEFAULT_USER_FNS,
    compile_lvs,
    lvs_validator,
)
from ndn.security import KeychainSqlite3, TpmFile


logging.basicConfig(
    format='[{asctime}]{levelname}:{message}',
    datefmt='%Y-%m-%d %H:%M:%S',
    level=logging.INFO,
    style='{',
)


LVS_TEXT = r'''
#KEY: "KEY"/_/_/_
#site: "lvs-test"
#article: #site/"article"/author/post/_version & {_version: $eq_type("v=0")} <= #author
#author: #site/"author"/author/"KEY"/_/admin/_ <= #admin
#admin: #site/"admin"/admin/#KEY <= #root
#root: #site/#KEY
'''


def main():
    basedir = os.path.dirname(os.path.abspath(sys.argv[0]))
    tpm_path = os.path.join(basedir, 'privKeys')
    pib_path = os.path.join(basedir, 'pib.db')
    keychain = KeychainSqlite3(pib_path, TpmFile(tpm_path))

    trust_anchor = keychain['/lvs-test'].default_key().default_cert()
    print(f'Trust anchor name: {enc.Name.to_str(trust_anchor.name)}')

    checker = Checker(compile_lvs(LVS_TEXT), DEFAULT_USER_FNS)
    app = ndn_app.NDNApp()
    validator = lvs_validator(checker, app, trust_anchor.data)

    async def fetch_article(article: str):
        try:
            name = enc.Name.from_str(f'/lvs-test/article/xinyu/{article}')
            print(f'Sending Interest {enc.Name.to_str(name)}')
            data_name, content, context = await app.express(
                name,
                validator=validator,
                must_be_fresh=True,
                can_be_prefix=True,
                lifetime=6000,
            )
            print(f'Received Data Name: {enc.Name.to_str(data_name)}')
            print(context['meta_info'])
            print(bytes(content).decode() if content else None)
        except types.InterestNack as exc:
            print(f'Nacked with reason={exc.reason}')
        except types.InterestTimeout:
            print('Timeout')
        except types.InterestCanceled:
            print('Canceled')
        except types.ValidationFailure:
            print('Data failed to validate')

    async def after_start():
        try:
            await fetch_article('hello')
            await fetch_article('world')
        finally:
            keychain.shutdown()
            app.shutdown()

    app.run_forever(after_start=after_start())


if __name__ == '__main__':
    main()
