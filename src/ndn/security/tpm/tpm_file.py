import os
from base64 import b64decode
from hashlib import sha256
from ...encoding import Signer
from ..sha256_rsa_signer import Sha256WithRsaSigner
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

    def get_signer(self, key_name: bytes) -> Signer:
        file_name = os.path.join(self.path, self._to_file_name(key_name))
        if not os.path.exists(file_name):
            raise KeyError(key_name)
        with open(file_name, 'rb') as f:
            key_b64 = f.read()
        key_der = b64decode(key_b64)
        return Sha256WithRsaSigner(key_name, key_der)
