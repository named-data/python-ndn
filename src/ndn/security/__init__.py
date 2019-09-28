from . import sha256_digest_signer
from . import sha256_rsa_signer


def initialize():
    sha256_digest_signer.register()
    sha256_rsa_signer.register()
