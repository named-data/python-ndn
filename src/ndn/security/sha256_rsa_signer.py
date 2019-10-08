from typing import List
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pkcs1_15
from ..encoding import Signer, SignatureType, KeyLocator, NonStrictName, VarBinaryStr


class Sha256WithRsaSigner(Signer):
    key_name: NonStrictName
    key_der: bytes

    def __init__(self, key_name: NonStrictName, key_der: bytes):
        self.key_name = key_name
        self.key_der = key_der

    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.SHA256_WITH_RSA
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_name

    def get_signature_value_size(self):
        key = RSA.import_key(self.key_der)
        return key.size_in_bytes()

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]):
        key = RSA.import_key(self.key_der)
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        signature = pkcs1_15.new(key).sign(h)
        wire[:] = signature
