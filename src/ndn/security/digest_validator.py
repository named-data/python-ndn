import logging
from hashlib import sha256
from typing import Dict, Any
from ..encoding import FormalName, SignatureType, Name, SignaturePtrs
from .validator import Validator


class DigestValidator(Validator):
    async def interest_validate(self, name: FormalName, sig: SignaturePtrs) -> bool:
        return True

    async def data_validate(self, name: FormalName, sig: SignaturePtrs) -> bool:
        sig_info = sig.signature_info
        covered_part = sig.signature_covered_part
        sig_value = sig.signature_value_buf
        if sig_info.signature_type == SignatureType.NOT_SIGNED:
            logging.debug('Reject not signed Data %s' % Name.to_str(name))
            return False
        elif sig_info.signature_type != SignatureType.DIGEST_SHA256:
            logging.debug('Accept without checking %s' % Name.to_str(name))
            return True
        else:
            sha256_algo = sha256()
            if not covered_part or not sig_value:
                ret = False
            else:
                for blk in covered_part:
                    sha256_algo.update(blk)
                ret = sha256_algo.digest() == sig_value
            logging.debug('Check %s -> %s' % (Name.to_str(name), ret))
            return ret
