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

from ndn import app, encoding as enc, utils
from ndn.app_support.light_versec import (
    Checker,
    DEFAULT_USER_FNS,
    compile_lvs,
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
    admin_cert = keychain['/lvs-test/admin/ndn'].default_key().default_cert()
    author_cert = keychain['/lvs-test/author/xinyu'].default_key().default_cert()
    print(f'Trust anchor name: {enc.Name.to_str(trust_anchor.name)}')
    print(f'Admin name: {enc.Name.to_str(admin_cert.name)}')
    print(f'Author name: {enc.Name.to_str(author_cert.name)}')

    checker = Checker(compile_lvs(LVS_TEXT), DEFAULT_USER_FNS)
    root_of_trust = checker.root_of_trust()
    ta_matches = {
        rule_name
        for rule_names, _ in checker.match(trust_anchor.name)
        for rule_name in rule_names
    }
    assert checker.validate_user_fns()
    assert root_of_trust.issubset(ta_matches)

    ndn_app = app.NDNApp()

    def serve_article(content: bytes):
        def on_interest(
            name: enc.FormalName,
            _app_param: enc.BinaryStr | None,
            reply: app.ReplyFunc,
            context: app.PktContext,
        ):
            print(f'>> I: {enc.Name.to_str(name)}, {context["int_param"]}')
            data_name = name + [enc.Component.from_version(utils.timestamp())]
            sign_cert_name = checker.suggest(data_name, keychain)
            if sign_cert_name is None:
                print(f'No signing certificate allowed for {enc.Name.to_str(data_name)}')
                return
            signer = keychain.get_signer({'cert': sign_cert_name})
            packet = ndn_app.make_data(
                data_name,
                content=content,
                signer=signer,
                freshness_period=10000,
            )
            if reply(packet):
                print(f'<< D: {enc.Name.to_str(data_name)}')
                print(f'Content: {content.decode()}')
                print()

        return on_interest

    ndn_app.route('/lvs-test/article/xinyu/hello')(
        serve_article(b'Hello,')
    )
    ndn_app.route('/lvs-test/article/xinyu/world')(
        serve_article(b'world!')
    )

    def serve_certificate(cert):
        @ndn_app.route(cert.name)
        def on_interest(
            _name: enc.FormalName,
            _app_param: enc.BinaryStr | None,
            reply: app.ReplyFunc,
            _context: app.PktContext,
        ):
            reply(cert.data)

    serve_certificate(trust_anchor)
    serve_certificate(admin_cert)
    serve_certificate(author_cert)

    print('Start serving ...')
    try:
        ndn_app.run_forever()
    finally:
        keychain.shutdown()


if __name__ == '__main__':
    main()
