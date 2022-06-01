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
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr, BinaryStr


class Ed25519Signer(Signer):
    key_locator_name: NonStrictName

    def __init__(self, key_locator_name: NonStrictName, key_bits: BinaryStr):
        self.key_locator_name = key_locator_name
        self.key = Ed25519PrivateKey.from_private_bytes(key_bits)

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.ED25519
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_locator_name

    def get_signature_value_size(self):
        return 64

    def write_signature_value(self, wire: VarBinaryStr, contents: list[VarBinaryStr]) -> int:
        # Copying is needed as cryptography library only support bytes
        c = b''.join(bytes(blk) for blk in contents)
        signature = self.key.sign(c)
        wire[:] = signature
        return len(signature)
