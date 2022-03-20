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
from ndn.contrib.boost_info import PropertyTree


class TestPropertyTree:
    @staticmethod
    def test_basic():
        text = r'''
                key1 value1
                key2
                {
                   key3 value3
                   {
                      key4 "value4 with spaces"
                   }
                   key5 value5
                }
                '''
        tree = PropertyTree.parse(text)
        root = tree.root
        assert len(root['key1']) == 1
        assert root['key1'][0].value == 'value1'
        assert len(root['key2']) == 1
        k2 = root['key2'][0]
        assert k2.value == ''
        assert k2.get('key3.key4') == 'value4 with spaces'
        assert k2.get_node('key5').value == 'value5'

    @staticmethod
    def test_full():
        text = r'''
                ; A comment
                key1 value1   ; Another comment
                key2
                {
                   subkey "value split "\
                          "over three"\
                          "lines"
                   {
                      a_key_without_value ""
                      "" value    ; Empty key with a value
                      "" ""       ; Empty key with empty value!
                   }
                }
                '''
        tree = PropertyTree.parse(text)
        root = tree.root
        assert len(root.children) == 2
        assert root.get('key1') == 'value1'
        # Special characters are not recognized
        assert root.get('key2.subkey') == 'value split over threelines'
        assert root.get('key2.subkey.a_key_without_value') == ''
        lst = root.get_node('key2.subkey')['']
        assert len(lst) == 2
        assert lst[0].value == 'value'
        assert lst[1].value == ''
