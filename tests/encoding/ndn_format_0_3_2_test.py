import hashlib

from ndn.encoding import Name
from ndn.encoding import ndn_format_0_3 as v1
from ndn.encoding.ndn_format_0_3_2 import (
    ContentType,
    InterestParam,
    MetaInfo,
    SignatureType,
    make_data,
    make_interest,
    parse_data,
    parse_interest,
)
from ndn.security import DigestSha256Signer, HmacSha256Signer


def test_default_interest_wire_format():
    wire = make_interest('/local/ndn/prefix', InterestParam())
    assert wire == (
        b'\x05\x1a\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix'
        b'\x0c\x02\x0f\xa0'
    )

    name, params, app_params, sig = parse_interest(wire)
    assert name == Name.from_str('/local/ndn/prefix')
    assert params.lifetime == 4000
    assert app_params is None
    assert sig.signature_info is None


def test_signed_interest_wire_format_and_coverage():
    wire = make_interest(
        '/local/ndn/prefix',
        InterestParam(nonce=0x6c211166),
        b'\x01\x02\x03\x04',
        DigestSha256Signer(),
    )
    assert wire == (
        b'\x05\x6f\x07\x36\x08\x05local\x08\x03ndn\x08\x06prefix'
        b'\x02 \x8e\x6e\x36\xd7\xea\xbc\xde\x43\x75\x61\x40\xc9'
        b'\x0b\xda\x09\xd5'
        b'\x00\xd2\xa5\x77\xf2\xf5\x33\xb5\x69\xf0\x44\x1d\xf0\xa7\xf9\xe2'
        b'\x0a\x04\x6c\x21\x11\x66\x0c\x02\x0f\xa0'
        b'\x24\x04\x01\x02\x03\x04\x2c\x03\x1b\x01\x00'
        b'\x2e \xea\xa8\xf0\x99\x08\x63\x78\x95\x1d\xe0\x5f\xf1'
        b'\xde\xbb\xc1\x18'
        b'\xb5\x21\x8b\x2f\xca\xa0\xb5\x1d\x18\xfa\xbc\x29\xf5\x4d\x58\xff'
    )

    _, _, _, sig = parse_interest(wire)
    assert sig.signature_info.signature_type == SignatureType.DIGEST_SHA256
    signature = hashlib.sha256(b''.join(sig.signature_covered_part)).digest()
    digest = hashlib.sha256(b''.join(sig.digest_covered_part)).digest()
    assert signature == sig.signature_value_buf
    assert digest == sig.digest_value_buf


def test_data_wire_format_and_coverage():
    wire = make_data(
        '/local/ndn/prefix', MetaInfo(), signer=DigestSha256Signer())
    assert wire == (
        b"\x06\x42\x07\x14\x08\x05local\x08\x03ndn\x08\x06prefix"
        b"\x14\x03\x18\x01\x00\x16\x03\x1b\x01\x00"
        b"\x17 \x7f1\xe4\t\xc5z/\x1d\r\xdaVh8\xfd\xd9\x94"
        b"\xd8\'S\x13[\xd7\x15\xa5\x9d%^\x80\xf2\xab\xf0\xb5"
    )

    name, meta_info, content, sig = parse_data(wire)
    assert name == Name.from_str('/local/ndn/prefix')
    assert meta_info.content_type == ContentType.BLOB
    assert content is None
    signature = hashlib.sha256(b''.join(sig.signature_covered_part)).digest()
    assert signature == sig.signature_value_buf


def test_key_locator_signer_matches_v1():
    signer = HmacSha256Signer('/local/KEY/1', b'secret')
    data = make_data('/local/data', MetaInfo(), b'content', signer=signer)
    assert data == v1.make_data('/local/data', v1.MetaInfo(), b'content', signer=signer)
    _, _, _, sig = parse_data(data)
    assert sig.signature_info.key_locator.name == Name.from_str('/local/KEY/1')

    interest = make_interest('/local/int', InterestParam(nonce=1), b'\x01', signer)
    assert interest == v1.make_interest(
        '/local/int', v1.InterestParam(nonce=1), b'\x01', signer)
