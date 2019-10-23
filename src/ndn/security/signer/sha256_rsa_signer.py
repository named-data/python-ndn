# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
from typing import List
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr


class Sha256WithRsaSigner(Signer):
    key_name: NonStrictName
    key_der: bytes

    def __init__(self, key_name: NonStrictName, key_der: bytes):
        self.key_name = key_name
        self.key_der = key_der
        self.key = RSA.import_key(self.key_der)

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.SHA256_WITH_RSA
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_name

    def get_signature_value_size(self):
        return self.key.size_in_bytes()

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]):
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        signature = pkcs1_15.new(self.key).sign(h)
        wire[:] = signature
