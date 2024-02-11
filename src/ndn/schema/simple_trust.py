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
from typing import Callable, Dict, Any
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import DSS, pkcs1_15
from Cryptodome.Hash import SHA256
from ..encoding import SignaturePtrs, FormalName, Name, SignatureType
from ..types import Validator, NetworkError, InterestTimeout, InterestNack, ValidationFailure
from .schema_tree import Node
from . import policy


Checker = Callable[[Dict[str, Any], Dict[str, Any]], bool]


class SignedBy(policy.DataValidator, policy.InterestValidator):
    r"""
    SignedBy policy represents the trust schema,
    specifying the key used to signed the Interest or Data packet.
    It does the follows:

    - Match the key used to sign the packet in the static tree.
      The real key must match the node specified by ``key``.
      Otherwise, the validation fails.
    - Call the checker ``subject_to`` with two matching variable dict.
      Fail if the checker returns ``False``.
    - Call the ``need`` function of the matched key node to get the public key.
      Fail if the key cannot be fetched.
    - Verify the signature.

    .. note::

        Theoretically, SignedBy should also give the signer used to sign outgoing packets.
        However, this function is missing in current implementation.

    For example,

    .. code-block:: python3

        # This checker checks the Author of Data is the same as the Author of the key.
        def check_author(data_env, key_env):
            return data_env['Author'] == key_env['Author']

        root = Node()
        root['/author/<Author>/KEY/<KeyID>/self/<CertID>'] = Node()
        root['/blog/<Author>/<Category>/<Date>'] = Node()
        # The Data "/blog/<Author>/<Category>/<Date>" should be signed by
        # the key "/author/<Author>/KEY/<KeyID>" with the same author.
        root['/blog/<Author>/<Category>/<Date>'].set_policy(
            policy.DataValidator,
            SignedBy(root['/author/<Author>/KEY/<KeyID>'], subject_to=check_author))
    """
    def __init__(self, key: Node, subject_to: Checker = None):
        super().__init__()
        self.key = key
        self.subject_to = subject_to
        self.logger = logging.getLogger(__name__)

    def get_validator(self, match) -> Validator:
        def validator(name: FormalName, sig_ptrs: SignaturePtrs):
            return self.validate(match.finer_match(name), sig_ptrs)
        return validator

    async def validate(self, match, sig_ptrs: SignaturePtrs) -> bool:
        # Check key name
        if sig_ptrs.signature_info is None or sig_ptrs.signature_info.key_locator is None:
            self.logger.info(f'{Name.to_str(match.name)} => Not signed')
            return False
        key_name = sig_ptrs.signature_info.key_locator.name
        if not key_name:
            self.logger.info(f'{Name.to_str(match.name)} => Not signed')
            return False
        key_match = match.root.match(key_name)
        if key_match.node is not self.key:
            self.logger.info(f'{Name.to_str(match.name)} => The key name {Name.to_str(key_name)} mismatch')
            return False
        if self.subject_to and not self.subject_to(match.env, key_match.env):
            self.logger.info(f'{Name.to_str(match.name)} => The key name {Name.to_str(key_name)} mismatch')
            return False
        # Get key_bits
        try:
            key_bits, _ = await key_match.need(must_be_fresh=True, can_be_prefix=True)
        except (NetworkError, InterestNack, InterestTimeout) as e:
            self.logger.info(f'{Name.to_str(match.name)} => Unable to fetch the key {Name.to_str(key_name)} due to {e}')
            return False
        except ValidationFailure:
            self.logger.info(f'{Name.to_str(match.name)} => The key {Name.to_str(key_name)} cannot be verified')
            return False
        # Import key
        sig_type = sig_ptrs.signature_info.signature_type
        key_bits = bytes(key_bits)
        try:
            if sig_type == SignatureType.SHA256_WITH_RSA:
                pub_key = RSA.import_key(key_bits)
                verifier = pkcs1_15.new(pub_key)
            elif sig_type == SignatureType.SHA256_WITH_ECDSA:
                pub_key = ECC.import_key(key_bits)
                verifier = DSS.new(pub_key, 'fips-186-3', 'der')
            else:
                self.logger.info(f'{Name.to_str(match.name)} => Unrecognized signature type {sig_type}')
                return False
        except (ValueError, IndexError, TypeError):
            self.logger.info(f'{Name.to_str(match.name)} => The key {Name.to_str(key_name)} is malformed')
            return False
        # Verify signature
        h = SHA256.new()
        for content in sig_ptrs.signature_covered_part:
            h.update(content)
        try:
            verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
        except ValueError:
            self.logger.info(f'{Name.to_str(match.name)} => Unable to verify the signature')
            return False
        self.logger.debug(f'{Name.to_str(match.name)} => Verification passed')
        return True
