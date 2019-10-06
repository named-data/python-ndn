from typing import List
from Cryptodome.Hash import SHA256
from ..encoding import Signer, SignatureType


class DigestSha256Signer(Signer):
    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.DIGEST_SHA256
        signature_info.key_locator = None

    def get_signature_value_size(self):
        return 32

    def write_signature_value(self, wire: memoryview, contents: List[memoryview]):
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        wire[:] = h.digest()
