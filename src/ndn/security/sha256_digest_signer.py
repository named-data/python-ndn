from typing import List
from ..encoding.signer import Signer
from ..encoding.ndn_format_0_3 import SignatureType
from Cryptodome.Hash import SHA256


class DigestSha256Signer(Signer):
    def write_signature_info(self, signature_info, **kwargs):
        signature_info.key_locator = None

    def get_signature_value_size(self, **kwargs):
        return 32

    def write_signature_value(self, wire: memoryview, contents: List[memoryview], **kwargs):
        hash = SHA256.new()
        for blk in contents:
            hash.update(blk)
        wire[:] = hash.digest()


def register():
    Signer.register(SignatureType.DIGEST_SHA256, DigestSha256Signer())
