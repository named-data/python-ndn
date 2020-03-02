import logging
from typing import Callable, Dict, Any
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Signature import DSS, pkcs1_15
from Cryptodome.Hash import SHA256
from ..encoding import SignaturePtrs, FormalName, Name, SignatureType
from ..types import Validator, NetworkError, InterestTimeout, InterestNack, ValidationFailure
from .schema_tree import MatchedNode, Node
from . import policy


Checker = Callable[[Dict[str, Any], Dict[str, Any]], bool]


class SignedBy(policy.DataValidator, policy.InterestValidator):
    def __init__(self, key: Node, subject_to: Checker = None):
        super().__init__()
        self.key = key
        self.subject_to = subject_to

    def get_validator(self, match) -> Validator:
        def validator(name: FormalName, sig_ptrs: SignaturePtrs):
            nonlocal match
            name_len = len(match.name)
            if match.pos == name_len:
                match = match.finer_match(name[name_len:])
            else:
                match = MatchedNode(root=match.root, node=match.node, name=name, pos=match.pos,
                                    env=match.env, policies=match.policies)
            return self.validate(match, sig_ptrs)
        return validator

    async def validate(self, match, sig_ptrs: SignaturePtrs) -> bool:
        # Check key name
        key_name = sig_ptrs.signature_info.key_locator.name
        if not key_name:
            logging.info(f'{Name.to_str(match.name)} => Not signed')
            return False
        key_match = match.root.match(key_name)
        if key_match.node is not self.key:
            logging.info(f'{Name.to_str(match.name)} => The key name {Name.to_str(key_name)} mismatch')
            return False
        if self.subject_to and not self.subject_to(match.env, key_match.env):
            logging.info(f'{Name.to_str(match.name)} => The key name {Name.to_str(key_name)} mismatch')
            return False
        # Get key_bits
        try:
            key_bits = await key_match.need(must_be_fresh=True, can_be_prefix=True)
        except (NetworkError, InterestNack, InterestTimeout) as e:
            logging.info(f'{Name.to_str(match.name)} => Unable to fetch the key {Name.to_str(key_name)} due to {e}')
            return False
        except ValidationFailure:
            logging.info(f'{Name.to_str(match.name)} => The key {Name.to_str(key_name)} cannot be verified')
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
                logging.info(f'{Name.to_str(match.name)} => Unrecognized signature type {sig_type}')
                return False
        except (ValueError, IndexError, TypeError):
            logging.info(f'{Name.to_str(match.name)} => The key {Name.to_str(key_name)} is malformed')
            return False
        # Verify signature
        h = SHA256.new()
        for content in sig_ptrs.signature_covered_part:
            h.update(content)
        try:
            verifier.verify(h, bytes(sig_ptrs.signature_value_buf))
        except ValueError:
            logging.info(f'{Name.to_str(match.name)} => Unable to verify the signature')
            return False
        logging.debug(f'{Name.to_str(match.name)} => Verification passed')
        return True
