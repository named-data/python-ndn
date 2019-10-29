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
from typing import List, Union
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ...encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr


class Sha256WithEcdsaSigner(Signer):
    # SHA256 doesn't work for P-384 and P-521
    key_name: NonStrictName
    key_der: bytes
    curve_bit: int
    key_size: int

    def __init__(self, key_name: NonStrictName, key_der: Union[bytes, str]):
        self.key_name = key_name
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
        signature_info.key_locator.name = self.key_name

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
