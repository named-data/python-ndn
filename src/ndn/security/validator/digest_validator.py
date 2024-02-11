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
        logging.getLogger(__name__).debug('Digest check %s -> %s' % (Name.to_str(name), ret))
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
    logging.getLogger(__name__).debug('Interest params-sha256 check %s -> %s' % (Name.to_str(name), ret))
    return ret


def union_checker(*args) -> Validator:
    async def wrapper(name: FormalName, sig: SignaturePtrs) -> bool:
        for checker in args:
            if not await checker(name, sig):
                return False
        return True
    return wrapper
