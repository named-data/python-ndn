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
import pytest
from ndn.app_support.light_versec import compile_lvs, Checker, SemanticError, DEFAULT_USER_FNS


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
    def test_redefinition():
        lvs = r'''
        #rule: "a"/b/"c"
        #rule: d/"e"/f
        '''
        with pytest.raises(SemanticError):
            Checker(compile_lvs(lvs), {})

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
