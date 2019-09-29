from typing import Callable, Dict, Any
from ..encoding import Signer
from .sha256_digest_signer import DigestSha256Signer


KeyChain = Callable[[Dict[str, Any]], Signer]


def make_digest_keychain() -> KeyChain:
    def get_signer(sign_args: Dict[str, Any]):
        if sign_args.pop('no_signature', False):
            return None
        else:
            return DigestSha256Signer()
    return get_signer
