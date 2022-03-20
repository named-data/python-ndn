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
import abc
from typing import Tuple, Optional
from Cryptodome.Hash import SHA256
from Cryptodome.Random import get_random_bytes
from ...app_support.security_v2 import KEY_COMPONENT
from ...encoding import Signer, NonStrictName, BinaryStr, FormalName, Component


class Tpm(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_signer(self, key_name: NonStrictName, key_locator_name: Optional[NonStrictName] = None) -> Signer:
        pass

    @abc.abstractmethod
    def generate_key(self, id_name: FormalName, key_type: str = 'rsa', **kwargs) -> Tuple[FormalName, BinaryStr]:
        pass

    @abc.abstractmethod
    def key_exist(self, key_name: FormalName) -> bool:
        pass

    @abc.abstractmethod
    def delete_key(self, key_name: FormalName):
        pass

    def construct_key_name(self, id_name: FormalName, pub_key: BinaryStr, **kwargs) -> FormalName:
        key_id = kwargs.get('key_id', None)
        key_id_type = kwargs.get('key_id_type', 'random')
        if not key_id:
            if key_id_type == 'random':
                while True:
                    key_id = Component.from_bytes(get_random_bytes(8))
                    if not self.key_exist(id_name + [KEY_COMPONENT, key_id]):
                        break
            elif key_id_type == 'sha256':
                h = SHA256.new()
                h.update(pub_key)
                key_id = Component.from_bytes(h.digest())
            else:
                raise ValueError(f'KeyIdType not supported: {key_id_type}')
        elif isinstance(key_id, str):
            key_id = Component.from_str(key_id)
        return id_name + [KEY_COMPONENT, key_id]
