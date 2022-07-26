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
from typing import List
from Cryptodome.Hash import SHA256
from ...encoding import Signer, SignatureType, VarBinaryStr
from ...utils import timestamp, gen_nonce_64


class DigestSha256Signer(Signer):
    for_interest: bool

    def __init__(self, for_interest: bool = False):
        self.for_interest = for_interest

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.DIGEST_SHA256
        signature_info.key_locator = None
        if self.for_interest:
            signature_info.signature_time = timestamp()
            signature_info.signature_nonce = gen_nonce_64()

    def get_signature_value_size(self):
        return 32

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        wire[:] = h.digest()
        return 32
