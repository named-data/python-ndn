from typing import List
from ..encoding.signer import Signer
from ..encoding.ndn_format_0_3 import SignatureType
from Cryptodome.Hash import SHA256


class DigestSha256Signer(Signer):
    def write_signature_info(self, signature_info, **kwargs):
        signature_info.signature_type = SignatureType.DIGEST_SHA256
        signature_info.key_locator = None

    def get_signature_value_size(self, **kwargs):
        return 32

    def write_signature_value(self, wire: memoryview, contents: List[memoryview], **kwargs):
        h = SHA256.new()
        for blk in contents:
            h.update(blk)
        wire[:] = h.digest()
