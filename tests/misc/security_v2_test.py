import dataclasses as dc
import hashlib
from datetime import UTC, datetime

from ndn.app_support.security_v2 import (
    CertificateV2SignatureInfo,
    CertificateV2Value,
    ContentType,
    SafeBag,
    SecurityV2TypeNumber,
    new_cert,
    parse_certificate,
)
from ndn.encoding import (
    Component,
    Name,
    SignatureType,
    tlv_encode,
    tlv_parse,
)
from ndn.encoding.ndn_format_0_3 import parse_data
from ndn.security import DigestSha256Signer, HmacSha256Signer


def test_certificate_models_use_dataclass_tlv_format():
    assert dc.is_dataclass(CertificateV2SignatureInfo)
    assert dc.is_dataclass(CertificateV2Value)
    assert dc.is_dataclass(SafeBag)


def test_new_cert_round_trip():
    start = datetime(2025, 1, 2, 3, 4, 5, tzinfo=UTC)
    end = datetime(2026, 2, 3, 4, 5, 6, tzinfo=UTC)
    cert_name, wire = new_cert(
        '/test/KEY/key-id',
        Component.from_str('issuer'),
        b'public-key',
        DigestSha256Signer(),
        start,
        end,
    )

    cert = parse_certificate(wire)
    assert cert.name == cert_name
    assert cert.content == b'public-key'
    assert cert.meta_info.content_type == ContentType.KEY
    assert cert.meta_info.freshness_period == 3600000
    assert cert.signature_info.signature_type == SignatureType.DIGEST_SHA256
    assert cert.signature_info.validity_period.not_before == b'20250102T030405'
    assert cert.signature_info.validity_period.not_after == b'20260203T040506'
    assert Name.is_prefix(Name.from_str('/test/KEY/key-id'), cert_name)

    _, _, _, sig = parse_data(wire)
    covered = b''.join(sig.signature_covered_part)
    assert hashlib.sha256(covered).digest() == sig.signature_value_buf


def test_new_cert_converts_legacy_signer_key_locator():
    _, wire = new_cert(
        '/test/KEY/key-id',
        Component.from_str('issuer'),
        b'public-key',
        HmacSha256Signer('/signer/key', b'secret'),
        datetime(2025, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 1, tzinfo=UTC),
    )

    cert = parse_certificate(wire)
    assert cert.signature_info.key_locator.name == Name.from_str('/signer/key')


def test_safe_bag_round_trip():
    safe_bag = SafeBag(certificate_v2=b'\x06\x00', encrypted_key_bag=b'key')
    wire = tlv_encode(safe_bag)

    assert wire == (
        bytes([0x06, 0x02, 0x06, 0x00])
        + bytes([SecurityV2TypeNumber.ENCRYPTED_KEY_BAG, 0x03])
        + b'key'
    )
    parsed = tlv_parse(SafeBag, wire)
    assert parsed.certificate_v2 == b'\x06\x00'
    assert parsed.encrypted_key_bag == b'key'
