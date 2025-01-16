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
import os
from datetime import datetime, timezone
import pytest
from tempfile import TemporaryDirectory
from ndn.encoding import Component
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS
from ndn.app_support.security_v2 import parse_certificate, derive_cert
from ndn.security import KeychainSqlite3, TpmFile


class TestLvsBasic:
    @staticmethod
    def test_compile():
        lvs = r'''
        #rule: "a"/b/"c"
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert checker.validate_user_fns()

    @staticmethod
    def test_temp_identifiers():
        lvs = r'''
        #_: "a"/b/"c"
        #_: d/"e"/f
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert checker.validate_user_fns()
        assert len(list(checker.match('/a/b/c'))) >= 1
        assert len(list(checker.match('/e/e/e'))) >= 1
        assert len(list(checker.match('/a/e/c'))) >= 2

        lvs = r'''
        #_: a/_/_/b/c & { b: a }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert checker.validate_user_fns()
        assert len(list(checker.match('/a/a/a/a/a'))) >= 1
        assert len(list(checker.match('/x/a/b/x/c'))) >= 1
        assert len(list(checker.match('/x/a/b/y/c'))) == 0

    @staticmethod
    def test_user_fns():
        lvs = r'''
        #r1: /a/b/c & { b: $eq(a), c: $eq_type("v=0") }
        '''
        checker = Checker(compile_lvs(lvs), DEFAULT_USER_FNS)
        assert checker.validate_user_fns()
        assert len(list(checker.match('/a/b/v=1'))) == 0
        assert len(list(checker.match('/e/e/v=1'))) == 1
        assert len(list(checker.match('/e/e/c'))) == 0

        lvs = r'''
        #r1: /a/b/c & { c: $eq(a, b), c: $eq_type("8=") }
        '''
        checker = Checker(compile_lvs(lvs), DEFAULT_USER_FNS)
        assert checker.validate_user_fns()
        assert len(list(checker.match('/a/b/c'))) == 0
        assert len(list(checker.match('/v=0/v=0/v=0'))) == 0
        assert len(list(checker.match('/e/e/e'))) == 1


class TestLvsSanity:
    @staticmethod
    def test_refer_to_temp():
        lvs = r'''
        #_r1: "a"/b/"c"
        #_r2: #_r1/d/"e"/f
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

        lvs = r'''
        #_: _a/b/c/d/e & { b: _a }
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

    @staticmethod
    def test_future_reference():
        lvs = r'''
        #_r1: a/b/c & { a: b }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert not list(checker.match('/a/b/c'))

        # lvs = r'''
        # #r1: "key"/a & { a: c }
        # #r2: "data"/c/d <= #r1
        # '''
        # with pytest.raises(SemanticError):
        #     Checker(compile_lvs(lvs), {})

    @staticmethod
    def test_cyclic_reference():
        lvs = r'''
        #rule1: a/#rule2
        #rule2: b/#rule1
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

        lvs = r'''
        #rule1: a <= #rule2
        #rule2: b <= #rule1
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

    @staticmethod
    def test_missing_definition():
        lvs = r'''
        #rule1: #rule2/a
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

        lvs = r'''
        #rule: a/b & { c: b }
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

        lvs = r'''
        #rule: a/b & { b: c }
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

        lvs = r'''
        #rule1: a <= #rule2
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

        lvs = r'''
        #_: a & { a: $fn() }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert not checker.validate_user_fns()


class TestLvsSemantics:
    @staticmethod
    def test_redefinition():
        lvs = r'''
        #rule: "a"/b/"c"
        #rule: d/"e"/f
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c'))) == 1
        assert len(list(checker.match('/d/e/f'))) == 1
        assert len(list(checker.match('/a/e/c'))) == 2

    @staticmethod
    def test_temp_pattern():
        lvs = r'''
        #r1: _a/b/_a
        #r2: #r1/_a & { _a: "xyz" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c/xyz'))) == 1
        assert len(list(checker.match('/a/b/c/d'))) == 0

        lvs = r'''
        #r1: _a/b/_a & { _a: "abc"|"def" }
        #r2: #r1/_a & { _a: "xyz" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/abc/b/abc/xyz'))) == 1
        assert len(list(checker.match('/abc/b/xyz/xyz'))) == 0
        assert len(list(checker.match('/abc/b/def/xyz'))) == 1

        lvs = r'''
        #r1: _a/b/_a
        #r2: /_a <= #r1
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert checker.check('/xyz', '/a/b/c')

    @staticmethod
    def test_named_pattern():
        lvs = r'''
        #r1: a/b/a
        #r2: #r1/a & { a: "xyz" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/xyz/b/xyz/xyz'))) == 1
        assert len(list(checker.match('/a/b/a/xyz'))) == 0
        assert len(list(checker.match('/a/b/a'))) == 1
        assert len(list(checker.match('/a/b/c'))) == 0

        lvs = r'''
        #r1: a/b/a & { a: "abc"|"def" }
        #r2: #r1/a & { a: "abc" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/abc/b/abc/abc'))) == 1
        assert len(list(checker.match('/def/b/def/abc'))) == 0
        assert len(list(checker.match('/def/b/def/def'))) == 0
        assert len(list(checker.match('/abc/b/def'))) == 0
        assert len(list(checker.match('/def/b/def'))) == 1

        lvs = r'''
        #r1: a/b/a
        #r2: /a <= #r1
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert not checker.check('/xyz', '/a/b/a')
        assert checker.check('/a', '/a/b/a')

    @staticmethod
    def test_rule_expansion():
        lvs = r'''
        #r1: a/_
        #r2: #r1/"c" & { a: "xyz" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/xyz/abc/c'))) == 1
        assert len(list(checker.match('/a/abc/c'))) == 0

        lvs = r'''
        #r1: a/_
        #r2: /"c"/#r1 & { a: "xyz" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/c/xyz/abc'))) == 1
        assert len(list(checker.match('/c/a/abc'))) == 0

        lvs = r'''
        #r1: a/_ & { a: "a"|"b" }
        #r2: #r1/_ & { a: "a"|"c" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c'))) >= 1
        assert len(list(checker.match('/b/c/a'))) == 0
        assert len(list(checker.match('/c/a/b'))) == 0
        assert len(list(checker.match('/a/b'))) >= 1
        assert len(list(checker.match('/b/c'))) >= 1
        assert len(list(checker.match('/c/a'))) == 0

        lvs = r'''
        #r1: a/_ & { a: "a" } | { a: "b" }
        #r2: #r1/_ & { a: "a" } | { a: "c" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c'))) >= 1
        assert len(list(checker.match('/b/c/a'))) == 0
        assert len(list(checker.match('/c/a/b'))) == 0
        assert len(list(checker.match('/a/b'))) >= 1
        assert len(list(checker.match('/b/c'))) >= 1
        assert len(list(checker.match('/c/a'))) == 0

        lvs = r'''
        #r1: a/_ & { a: "a" } | { a: "b" }
        #r2: #r1/c & { c: "c" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c'))) >= 1
        assert len(list(checker.match('/b/c/c'))) >= 1
        assert len(list(checker.match('/c/a/c'))) == 0

        lvs = r'''
        #r1: a/b & { a: "a" } | { b: "b" }
        #r2: #r1/c & { c: "c" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c'))) >= 1
        assert len(list(checker.match('/b/b/c'))) >= 1
        assert len(list(checker.match('/a/a/c'))) >= 1

    @staticmethod
    def test_complicated_rule():
        lvs = r'''
        #r1: a/b/c & { c: b, c: a, a: "a"|"x" } | { b: "b"|"y" } <= #r2 | #r3
        #r2: x/y/z & { x: "xxx" }
        #r3: x/y/z & { y: "yyy" }
        '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/a/b/c'))) >= 1
        assert len(list(checker.match('/x/y/z'))) >= 1
        assert len(list(checker.match('/x/x/x'))) >= 1
        assert len(list(checker.match('/a/a/a'))) >= 1
        assert len(list(checker.match('/a/c/a'))) == 0
        assert len(list(checker.match('/a/x/x'))) == 0
        assert checker.check('/a/b/c', '/xxx/yyy/zzz')
        assert checker.check('/x/y/z', '/xxx/xxx/xxx')
        assert checker.check('/x/x/x', '/xxx/yyy/zzz')
        assert checker.check('/a/a/a', '/xxx/xxx/xxx')

    @staticmethod
    def test_signing_suggest():
        with TemporaryDirectory() as tmpdirname:
            pib_file = os.path.join(tmpdirname, 'pib.db')
            tpm_dir = os.path.join(tmpdirname, 'privKeys')
            KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
            keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))
            assert len(keychain) == 0

            la_id = keychain.touch_identity('/la')
            la_cert = la_id.default_key().default_cert().data
            la_cert_data = parse_certificate(la_cert)
            la_cert_name = la_cert_data.name
            la_signer = keychain.get_signer({'cert': la_cert_name})

            la_author_id = keychain.touch_identity('/la/author/1')
            la_author_cert_name, la_author_cert = derive_cert(la_author_id.default_key().name,
                                                              Component.from_str('la-signer'),
                                                              la_cert_data.content, la_signer,
                                                              datetime.now(timezone.utc), 100)
            keychain.import_cert(la_id.default_key().name, la_author_cert_name, la_author_cert)

            ny_id = keychain.touch_identity('/ny')
            ny_cert = ny_id.default_key().default_cert().data
            ny_cert_data = parse_certificate(ny_cert)
            ny_cert_name = ny_cert_data.name
            ny_signer = keychain.get_signer({'cert': ny_cert_name})

            ny_author_id = keychain.touch_identity('/ny/author/2')
            ny_author_cert_name, ny_author_cert = derive_cert(ny_author_id.default_key().name,
                                                              Component.from_str('ny-signer'),
                                                              ny_cert_data.content, ny_signer,
                                                              datetime.now(timezone.utc), 100)
            keychain.import_cert(ny_id.default_key().name, ny_author_cert_name, ny_author_cert)

            lvs = r'''
            #KEY: "KEY"/_/_/_
            #article: /"article"/_topic/_ & { _topic: "eco" | "spo" } <= #author
            #author: /site/"author"/_/#KEY <= #anchor
            #anchor: /site/#KEY & {site: "la" | "ny" }
            '''
            checker = Checker(compile_lvs(lvs), {})

            assert checker.suggest("/article/eco/day1", keychain) == la_author_cert_name
            assert checker.suggest("/article/life/day1", keychain) is None

            lvs = r'''
            #KEY: "KEY"/_/_/_
            #LAKEY: "KEY"/_/_signer/_ & { _signer: "la-signer" }
            #article: /"article"/_topic/_ & { _topic: "eco" | "spo" } <= #author
            #author: /site/"author"/_/#LAKEY <= #anchor
            #anchor: /site/#KEY & {site: "la"}
            '''
            checker = Checker(compile_lvs(lvs), {})
            assert checker.suggest("/article/eco/day1", keychain) == la_author_cert_name

            lvs = r'''
            #KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
            #article: /"article"/_topic/_ & { _topic: "life" | "fin" } <= #author
            #author: /site/"author"/_/#KEY & { site: "ny" } <= #anchor
            #anchor: /site/#KEY & { site: "ny" }
            '''
            checker = Checker(compile_lvs(lvs), DEFAULT_USER_FNS)
            assert checker.suggest("/article/fin/day1", keychain) == ny_author_cert_name

            lvs = r'''
            #KEY: "KEY"/_/_/_version & { _version: $eq_type("v=0") }
            #NYKEY: "KEY"/_/_signer/_version& { _signer: "ny-signer", _version: $eq_type("v=0")}
            #article: /"article"/_topic/_ <= #author
            #author: /site/"author"/_/#NYKEY <= #anchor
            #anchor: /site/#KEY & {site: "ny"}
            #site: "ny"
            '''
            checker = Checker(compile_lvs(lvs), DEFAULT_USER_FNS)
            assert checker.suggest("/article/eco/day1", keychain) == ny_author_cert_name

    @staticmethod
    def test_complicated_redef():
        lvs = r'''
            #network: network & { network: "ndn" | "yoursunny" }
            #CERT: "KEY"/_/_/_
            #sitename: s1
            #sitename: s1/s2
            #sitename: s1/s2/s3

            #routername: #network/#sitename/"%C1.Router"/routerid
            #rootcert: #network/#CERT
            #sitecert: #network/#sitename/#CERT <= #rootcert
            #operatorcert: #network/#sitename/"%C1.Operator"/opid/#CERT <= #sitecert
            #routercert: #routername/#CERT <= #operatorcert
            #lsdbdata: #routername/"nlsr"/"lsdb"/lsatype/version/segment <= #routercert
            '''
        checker = Checker(compile_lvs(lvs), {})
        assert len(list(checker.match('/ndn/KEY/1/self/1'))) == 1
        assert len(list(checker.match('/ndn/ucla/KEY/1/self/1'))) == 1
        assert len(list(checker.match('/ndn/ucla/cs/KEY/1/self/1'))) == 1
        assert len(list(checker.match('/ndn/ucla/cs/irl/KEY/1/self/1'))) == 1
        assert len(list(checker.match('/ndn/ucla/cs/irl/should-fail/KEY/1/self/1'))) == 0

        assert checker.check('/ndn/ucla/KEY/2/ndn/3', '/ndn/KEY/1/self/1')
        # Operator
        assert checker.check('/ndn/ucla/%C1.Operator/13/KEY/2/ndn/3', '/ndn/ucla/KEY/2/ndn/3')
        assert checker.check('/ndn/ucla/cs/%C1.Operator/13/KEY/2/ndn/3', '/ndn/ucla/cs/KEY/2/ndn/3')
        # Operator is also matched as a site
        assert checker.check('/ndn/ucla/%C1.Operator/13/KEY/2/ndn/3', '/ndn/KEY/1/self/1')
        # No cross-site issuance
        assert not checker.check('/ndn/ucla/%C1.Operator/13/KEY/2/ndn/3', '/ndn/arizona/KEY/2/ndn/3')
        assert not checker.check('/ndn/ucla/%C1.Operator/13/KEY/2/ndn/3', '/yoursunny/ucla/KEY/2/ndn/3')
        # But super-zone can sign sub-zone
        assert checker.check('/ndn/ucla/cs/%C1.Operator/13/KEY/2/ndn/3', '/ndn/ucla/KEY/2/ndn/3')
        assert not checker.check('/ndn/ucla/cs/%C1.Operator/13/KEY/2/ndn/3', '/ndn/ucla/ee/KEY/2/ndn/3')