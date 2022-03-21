import os
import sys
import logging
from ndn.utils import timestamp
from ndn.encoding import Name, Component
from ndn.security import TpmFile, KeychainSqlite3
from ndn.app import NDNApp
from ndn.app_support.light_versec import compile_lvs, Checker, DEFAULT_USER_FNS


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')

lvs_text = r'''
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
    print(f'Trust anchor name: {Name.to_str(trust_anchor.name)}')
    print(f'Admin name: {Name.to_str(admin_cert.name)}')
    print(f'Author name: {Name.to_str(author_cert.name)}')

    lvs_model = compile_lvs(lvs_text)
    checker = Checker(lvs_model, DEFAULT_USER_FNS)
    # The following manual checks are listed for demonstration only.
    # In real implementation they are automatically done
    root_of_trust = checker.root_of_trust()
    print(f'LVS model root of trust: {root_of_trust}')
    print(f'LVS model user functions provided: {checker.validate_user_fns()}')
    ta_matches = sum((m[0] for m in checker.match(trust_anchor.name)), start=[])
    assert len(ta_matches) > 0
    assert root_of_trust.issubset(ta_matches)
    print(f'Trust anchor matches the root of trust: OK')

    app = NDNApp(keychain=keychain)

    @app.route('/lvs-test/article/xinyu/hello')
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        content = "Hello,".encode()
        data_name = name + [Component.from_version(timestamp())]
        app.put_data(data_name, content=content, freshness_period=10000)
        print(f'<< D: {Name.to_str(data_name)}')
        print(f'Content: {content.decode()}')
        print('')

    @app.route('/lvs-test/article/xinyu/world')
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        content = "world!".encode()
        data_name = name + [Component.from_version(timestamp())]
        app.put_data(data_name, content=content, freshness_period=10000)
        print(f'<< D: {Name.to_str(data_name)}')
        print(f'Content: {content.decode()}')
        print('')

    @app.route(trust_anchor.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(trust_anchor.data)
        print(f'<< D: {Name.to_str(trust_anchor.name)}')
        print('')

    @app.route(admin_cert.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(admin_cert.data)
        print(f'<< D: {Name.to_str(admin_cert.name)}')
        print('')

    @app.route(author_cert.name)
    def on_interest(name, param, _app_param):
        print(f'>> I: {Name.to_str(name)}, {param}')
        app.put_raw_packet(author_cert.data)
        print(f'<< D: {Name.to_str(author_cert.name)}')
        print('')

    print('Start serving ...')
    app.run_forever()


if __name__ == '__main__':
    main()
