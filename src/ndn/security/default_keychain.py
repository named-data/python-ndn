from typing import Dict, Any
from .sha256_digest_signer import DigestSha256Signer


class DefaultKeyChain:
    def __call__(self, sign_args: Dict[str, Any]):
        if sign_args.pop('no_signature', False):
            return None
        if sign_args.pop('digest_sha256', False):
            return DigestSha256Signer()
