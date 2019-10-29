from Cryptodome.Util.asn1 import DerSequence
from Cryptodome.PublicKey import ECC
from ndn.encoding import make_data, MetaInfo, parse_data
from ndn.security import Sha256WithEcdsaSigner, Sha256WithRsaSigner, HmacSha256Signer


class TestSha256WithEcdsaSigner:
    def test_der_format(self):
        # Ecdsa signature is not unique, so we only test the format
        key = ECC.generate(curve="P-256").export_key(format="DER")
        signer = Sha256WithEcdsaSigner("/K/KEY/x", key)
        pkt = make_data("/A", MetaInfo(), signer=signer)
        _, _, _, sig_ptrs = parse_data(pkt)
        DerSequence().decode(bytes(sig_ptrs.signature_value_buf))
