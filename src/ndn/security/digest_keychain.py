from typing import Dict, Any
from ..types import KeyChain
from .sha256_digest_signer import DigestSha256Signer


def make_digest_keychain() -> KeyChain:
    def get_signer(sign_args: Dict[str, Any]):
        if sign_args.pop('no_signature', False):
            return None
        else:
            return DigestSha256Signer()
    return get_signer
