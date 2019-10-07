import logging
from hashlib import sha256
from ..encoding import FormalName, SignatureType, Name, SignaturePtrs
from ..types import Validator


async def sha256_digest_checker(name: FormalName, sig: SignaturePtrs) -> bool:
    sig_info = sig.signature_info
    covered_part = sig.signature_covered_part
    sig_value = sig.signature_value_buf
    if sig_info and sig_info.signature_type == SignatureType.DIGEST_SHA256:
        sha256_algo = sha256()
        if not covered_part or not sig_value:
            ret = False
        else:
            for blk in covered_part:
                sha256_algo.update(blk)
            ret = sha256_algo.digest() == sig_value
        logging.debug('Digest check %s -> %s' % (Name.to_str(name), ret))
        return ret
    else:
        return True


# This is automatically called
async def params_sha256_checker(name: FormalName, sig: SignaturePtrs) -> bool:
    covered_part = sig.digest_covered_part
    sig_value = sig.digest_value_buf
    sha256_algo = sha256()
    if not covered_part or not sig_value:
        ret = False
    else:
        for blk in covered_part:
            sha256_algo.update(blk)
        ret = sha256_algo.digest() == sig_value
    logging.debug('Interest params-sha256 check %s -> %s' % (Name.to_str(name), ret))
    return ret


def union_checker(*args) -> Validator:
    async def wrapper(name: FormalName, sig: SignaturePtrs) -> bool:
        for checker in args:
            if not await checker(name, sig):
                return False
        return True
    return wrapper
