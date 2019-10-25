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
import os
from base64 import b64decode
from hashlib import sha256
from ...encoding import Signer, NonStrictName, Name
from ..signer.sha256_rsa_signer import Sha256WithRsaSigner
from ..signer.sha256_ecdsa_signer import Sha256WithEcdsaSigner
from .tpm import Tpm


class TpmFile(Tpm):
    path: str

    def __init__(self, path):
        self.path = path

    @staticmethod
    def _to_file_name(key_name: bytes):
        algo = sha256()
        algo.update(key_name)
        return algo.digest().hex() + '.privkey'

    def get_signer(self, key_name: NonStrictName) -> Signer:
        key_name = Name.to_bytes(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        if not os.path.exists(file_name):
            raise KeyError(key_name)
        with open(file_name, 'rb') as f:
            key_b64 = f.read()
        key_der = b64decode(key_b64)
        for signer in [Sha256WithRsaSigner, Sha256WithEcdsaSigner]:
            try:
                return signer(key_name, key_der)
            except ValueError:
                pass
        raise ValueError('Key format is not supported')
