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
import abc
import logging
from typing import Optional, Coroutine, Any
from Cryptodome.PublicKey import ECC, RSA
from ...encoding import FormalName, BinaryStr, SignatureType, Name, parse_data, SignaturePtrs
from ...app import NDNApp, Validator, ValidationFailure, InterestTimeout, InterestNack
from .known_key_validator import verify_rsa, verify_hmac, verify_ecdsa


class PublicKeyStorage(abc.ABC):
    @abc.abstractmethod
    def load(self, name: FormalName) -> Optional[bytes]:
        pass

    @abc.abstractmethod
    def save(self, name: FormalName, key_bits: bytes):
        pass


class EmptyKeyStorage(PublicKeyStorage):
    def load(self, name: FormalName) -> Optional[bytes]:
        return None

    def save(self, name: FormalName, key_bits: bytes):
        return


class MemoryKeyStorage(PublicKeyStorage):
    _cache: dict[bytes, bytes]

    def __init__(self):
        self._cache = {}

    def load(self, name: FormalName) -> Optional[bytes]:
        return self._cache.get(Name.to_bytes(name), None)

    def save(self, name: FormalName, key_bits: bytes):
        self._cache[Name.to_bytes(name)] = key_bits


class CascadeChecker:
    app: NDNApp
    next_level: Validator
    storage: Optional[PublicKeyStorage]
    anchor_key: bytes
    anchor_name: FormalName

    @staticmethod
    def _verify_sig(pub_key_bits, sig_ptrs) -> bool:
        if sig_ptrs.signature_info.signature_type == SignatureType.HMAC_WITH_SHA256:
            verify_hmac(pub_key_bits, sig_ptrs)
        elif sig_ptrs.signature_info.signature_type == SignatureType.SHA256_WITH_RSA:
            pub_key = RSA.import_key(bytes(pub_key_bits))
            return verify_rsa(pub_key, sig_ptrs)
        elif sig_ptrs.signature_info.signature_type == SignatureType.SHA256_WITH_ECDSA:
            pub_key = ECC.import_key(bytes(pub_key_bits))
            return verify_ecdsa(pub_key, sig_ptrs)
        else:
            return False

    def __init__(self, app: NDNApp, trust_anchor: BinaryStr, storage: PublicKeyStorage = MemoryKeyStorage()):
        self.app = app
        self.next_level = self
        self.storage = storage
        cert_name, _, key_bits, sig_ptrs = parse_data(trust_anchor)
        self.anchor_name = [bytes(c) for c in cert_name]  # Copy the name in case
        self.anchor_key = bytes(key_bits)
        if not self._verify_sig(self.anchor_key, sig_ptrs):
            raise ValueError('Trust anchor is not properly self-signed')
        self.logger = logging.getLogger(__name__)

    async def validate(self, name: FormalName, sig_ptrs: SignaturePtrs) -> bool:
        if (not sig_ptrs.signature_info or not sig_ptrs.signature_info.key_locator
                or not sig_ptrs.signature_info.key_locator.name):
            return False
        # Obtain public key
        cert_name = sig_ptrs.signature_info.key_locator.name
        self.logger.debug(f'Verifying {Name.to_str(name)} <- {Name.to_str(cert_name)} ...')
        if cert_name == self.anchor_name:
            self.logger.debug('Use trust anchor.')
            key_bits = self.anchor_key
        else:
            if key_bits := self.storage.load(cert_name):
                self.logger.debug('Use cached public key.')
            else:
                self.logger.debug('Cascade fetching public key ...')
                # Try to fetch
                try:
                    _, _, key_bits = await self.app.express_interest(
                        name=cert_name, must_be_fresh=True, can_be_prefix=False,
                        validator=self.next_level)
                except (ValidationFailure, InterestTimeout, InterestNack):
                    self.logger.debug('Public key not valid.')
                    return False
                self.logger.debug('Public key fetched.')
                if key_bits:
                    self.storage.save(cert_name, key_bits)
        # Validate signature
        if not key_bits:
            return False
        return self._verify_sig(key_bits, sig_ptrs)

    def __call__(self, name: FormalName, sig_ptrs: SignaturePtrs) -> Coroutine[Any, None, bool]:
        return self.validate(name, sig_ptrs)
