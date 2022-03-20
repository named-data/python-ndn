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
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr


class Sha256WithEcdsaSigner(Signer):
    # SHA256 doesn't work for P-384 and P-521
    key_locator_name: NonStrictName
    key_der: bytes
    curve_bit: int
    key_size: int

    def __init__(self, key_locator_name: NonStrictName, key_der: Union[bytes, str]):
        self.key_locator_name = key_locator_name
        self.key_der = key_der
        self.key = ECC.import_key(self.key_der)
        curve = self.key.curve
        if curve[-2:] == 'r1' or curve[-2:] == 'v1':
            self.curve_bit = int(curve[-5:-2])
        else:
            self.curve_bit = int(curve[-3:])
        self.key_size = (self.curve_bit * 2 + 7) // 8
        self.key_size += self.key_size % 2

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.SHA256_WITH_ECDSA
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_locator_name

    def get_signature_value_size(self):
        return self.key_size + 8

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        signature = DSS.new(self.key, 'fips-186-3', 'der').sign(h)
        real_len = len(signature)
        wire[:real_len] = signature
        return real_len
