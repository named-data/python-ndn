from Cryptodome.PublicKey import ECC
from Cryptodome.Random import get_random_bytes
from ndn.app_support.ecies import encrypt, decrypt


class TestEcies:
    def test_r256(self):
        priv_key = ECC.generate(curve='secp256r1')
        data = get_random_bytes(100)
        pub_key = priv_key.public_key()
        cipher_text = encrypt(pub_key, data)
        plain_text = decrypt(priv_key, cipher_text)
        assert plain_text == data

    def test_ed25519(self):
        priv_key = ECC.generate(curve='ed25519')
        data = get_random_bytes(100)
        pub_key = priv_key.public_key()
        cipher_text = encrypt(pub_key, data)
        plain_text = decrypt(priv_key, cipher_text)
        assert plain_text == data
