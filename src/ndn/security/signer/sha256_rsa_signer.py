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
from typing import List, Union
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr


class Sha256WithRsaSigner(Signer):
    key_locator_name: NonStrictName
    key_der: bytes

    def __init__(self, key_locator_name: NonStrictName, key_der: Union[str, bytes]):
        self.key_locator_name = key_locator_name
        self.key_der = key_der
        self.key = RSA.import_key(self.key_der)

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.SHA256_WITH_RSA
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_locator_name

    def get_signature_value_size(self):
        return self.key.size_in_bytes()

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        signature = pkcs1_15.new(self.key).sign(h)
        wire[:] = signature
        return len(signature)
