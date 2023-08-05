# This file is modified from eciespy <https://github.com/ecies/py>
# under MIT License
#
# Copyright (c) 2018-2021 Weiliang Li
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.PublicKey import ECC
from Cryptodome.Protocol.KDF import HKDF
from ..types import BinaryStr

# Security notes:
# ECIES is the equivalent to ECDH with an emphiral key.
# And it is OK to use the same key for both DSA and Diffie-Hellman for curve P-256 and ed25519.
# Differences from original code:
# - Use different libraries
# - Use secp256r1 and ed25519 instead of secp256k1


def get_key_length(key: ECC.EccKey) -> int:
    if key.curve == 'NIST P-256' or key.curve == 'Ed25519':
        return 32
    elif key.curve == 'NIST P-384':
        return 48
    elif key.curve == 'Ed448':
        return 56
    else:
        raise ValueError(f'Unsupported curve for ECIES: {key.curve}')


def encrypt(pub_key: ECC.EccKey, content: BinaryStr) -> bytes:
    """
    Encrypt a message with an ECC key

    :param pub_key: the public key, using the curve secp256r1 or ed25519.
    :param content: the message to encrypt.
    :return: cipher text.
    """
    key_len = get_key_length(pub_key)
    # ephemeral key
    ek = ECC.generate(curve=pub_key.curve)
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = pub_key.pointQ * ek.d
    p_bytes = int(p.x).to_bytes(key_len, 'big') + int(p.y).to_bytes(key_len, 'big')
    ek_q = ek.public_key().pointQ
    ek_q_bytes = int(ek_q.x).to_bytes(key_len, 'big') + int(ek_q.y).to_bytes(key_len, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM)

    encrypted, tag = cipher.encrypt_and_digest(content)
    ret = bytearray()
    ret.extend(ek_q_bytes)
    ret.extend(cipher.nonce)
    ret.extend(tag)
    ret.extend(encrypted)
    return bytes(ret)


def decrypt(pri_key: ECC.EccKey, cipher_text: BinaryStr) -> bytes:
    """
    Decrypt a message encrypted with an ECC key.

    :param pri_key: the private key, using curve secp256r1.
    :param cipher_text: the cipher text.
    :return: decrypted message.
    :raises ValueError: if the decryption failed.
    """
    key_len = get_key_length(pri_key)
    aes_offset = key_len*2
    ek_q_bytes = bytes(cipher_text[0:aes_offset])
    nonce = bytes(cipher_text[aes_offset:aes_offset+16])
    tag = cipher_text[aes_offset+16:aes_offset+32]
    encrypted = cipher_text[aes_offset+32:]

    # ephemeral key
    ek_q = ECC.EccPoint(x=int.from_bytes(ek_q_bytes[:key_len], 'big'),
                        y=int.from_bytes(ek_q_bytes[key_len:], 'big'),
                        curve=pri_key.curve)
    # ek.d * pub_key.Q = ek.public_key.Q * pri_key.d
    p = ek_q * pri_key.d
    p_bytes = int(p.x).to_bytes(key_len, 'big') + int(p.y).to_bytes(key_len, 'big')
    master = ek_q_bytes + p_bytes
    derived = HKDF(master, 32, b'', SHA256)
    cipher = AES.new(derived, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(encrypted, tag)
