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
import logging
from hashlib import sha256
from ...encoding import FormalName, SignatureType, Name, SignaturePtrs
from ...types import Validator


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
