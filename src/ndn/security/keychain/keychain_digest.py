from .keychain import Keychain
from typing import Dict, Any
from ..sha256_digest_signer import DigestSha256Signer


class KeychainDigest(Keychain):
    def get_signer(self, sign_args: Dict[str, Any]):
        if sign_args.pop('no_signature', False):
            return None
        else:
            return DigestSha256Signer()
