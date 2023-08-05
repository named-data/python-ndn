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
from Cryptodome.PublicKey import ECC
from Cryptodome.Hash import SHA512
from Cryptodome.Signature import eddsa
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr, BinaryStr


class Ed25519Signer(Signer):
    key_locator_name: NonStrictName

    def __init__(self, key_locator_name: NonStrictName, key_bits: BinaryStr):
        """
        Create an Ed25519Signer

        .. note::
            `key_bits` must be DER format. If you have a 32B raw key bits,
            prepend it with `b'0.\x02\x01\x000\x05\x06\x03+ep\x04"\x04 '`.
        """
        self.key_locator_name = key_locator_name
        self.key = ECC.import_key(bytes(key_bits))

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.ED25519
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_locator_name

    def get_signature_value_size(self):
        return 64

    def write_signature_value(self, wire: VarBinaryStr, contents: list[VarBinaryStr]) -> int:
        # Copying is needed as cryptography library only support bytes
        h = SHA512.new()
        for blk in contents:
            h.update(blk)
        signer = eddsa.new(self.key, 'rfc8032')
        signature = signer.sign(h)
        wire[:] = signature
        return len(signature)
