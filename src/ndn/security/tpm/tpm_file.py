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
import os
from base64 import b64decode, b64encode
from hashlib import sha256
from typing import Tuple, Optional
from Cryptodome.PublicKey import RSA, ECC
from ...encoding import Signer, NonStrictName, Name, BinaryStr, FormalName
from ..signer.sha256_rsa_signer import Sha256WithRsaSigner
from ..signer.sha256_ecdsa_signer import Sha256WithEcdsaSigner
from .tpm import Tpm


class TpmFile(Tpm):
    path: str

    def __init__(self, path):
        self.path = path

    @staticmethod
    def _to_file_name(key_name: bytes):
        return sha256(key_name).digest().hex() + '.privkey'

    @staticmethod
    def _base64_newline(src: bytes):
        return b'\n'.join(src[i*64:i*64+64] for i in range((len(src) + 63) // 64))

    def get_signer(self, key_name: NonStrictName, key_locator_name: Optional[NonStrictName] = None) -> Signer:
        key_name = Name.to_bytes(key_name)
        if key_locator_name is None:
            key_locator_name = key_name
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        if not os.path.exists(file_name):
            raise KeyError(key_name)
        with open(file_name, 'rb') as f:
            key_b64 = f.read()
        key_der = b64decode(key_b64)
        for signer in [Sha256WithRsaSigner, Sha256WithEcdsaSigner]:
            try:
                return signer(key_locator_name, key_der)
            except ValueError:
                pass
        raise ValueError('Key format is not supported')

    def key_exist(self, key_name: FormalName) -> bool:
        key_name = Name.encode(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        return os.path.exists(file_name)

    def save_key(self, key_name: FormalName, key_der: BinaryStr):
        key_name = Name.encode(key_name)
        key_b64 = self._base64_newline(b64encode(key_der))
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        with open(file_name, 'wb') as f:
            f.write(key_b64)

    def delete_key(self, key_name: FormalName):
        key_name = Name.encode(key_name)
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        try:
            os.remove(file_name)
        except FileNotFoundError:
            pass

    def generate_key(self, id_name: FormalName, key_type: str = 'rsa', **kwargs) -> Tuple[FormalName, BinaryStr]:
        if key_type == 'rsa':
            siz = kwargs.pop('key_size', 2048)
            pri_key = RSA.generate(siz)
            pub_key = pri_key.publickey().export_key(format='DER')
            key_der = pri_key.export_key(format='DER', pkcs=1)
        elif key_type == 'ec':
            siz = kwargs.pop('key_size', 256)
            pri_key = ECC.generate(curve=f'P-{siz}')
            pub_key = bytes(pri_key.public_key().export_key(format='DER'))
            key_der = pri_key.export_key(format='DER', use_pkcs8=False)
        else:
            raise ValueError(f'Unsupported key type {key_type}')
        key_name = self.construct_key_name(id_name, pub_key, **kwargs)
        self.save_key(key_name, key_der)
        return key_name, pub_key
