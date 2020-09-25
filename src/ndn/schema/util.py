# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
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
from typing import Union, List, Tuple
from ..encoding import Name, Component, BinaryStr

NamePattern = List[Union[BinaryStr, Tuple[int, int, str]]]
r"""
NamePattern is a list containing mixed name components and varaible patterns.
A variable pattern is a capturing pattern that matches with exactly one name component.
It is a tuple containing 3 variables:

- The 1st element is reserved and always 0. This is a quick and dirty solution in this PoC implementation
  It will be used if we want to support multiple name components matching patterns.
- The 2nd element is the TLV type of the name component to be matched.
- The 3rd element is the name of the pattern variable.
"""


def norm_pattern(name: str) -> NamePattern:
    """
    This function returns a normalized name pattern from a string, just like normalizing a name.

    :param name: the name pattern string.
    :return: normalized name pattern.
    """
    ret = Name.normalize(name)[:]
    for i, comp in enumerate(ret):
        comp_type = Component.get_type(comp)
        comp_value = Component.get_value(comp)
        if comp_type == Component.TYPE_GENERIC and comp_value[0] == b'<'[0] and comp_value[-1] == b'>'[0]:
            content = bytes(comp_value[1:-1]).decode()
            eq_sgn = content.find(':')
            if eq_sgn >= 0:
                type_str = content[:eq_sgn]
                if type_str == 'sha256digest':
                    type_val = Component.TYPE_IMPLICIT_SHA256
                elif type_str == 'params-sha256':
                    type_val = Component.TYPE_PARAMETERS_SHA256
                elif type_str in Component.ALTERNATE_URI_STR:
                    type_val = Component.ALTERNATE_URI_STR[type_str]
                else:
                    type_val = int(type_str)
                content = content[eq_sgn+1:]
            else:
                type_val = Component.TYPE_GENERIC
            if not content:
                raise ValueError('Pattern variable name cannot be empty')
            ret[i] = (0, type_val, content)
    return ret
