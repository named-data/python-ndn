# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# -----------------------------------------------------------------------------
import dataclasses as dc
from datetime import datetime, timedelta, UTC

from ..utils import timestamp
from ..encoding import (
    Component,
    FormalName,
    Name,
    VarBinaryStr,
    parse_and_check_tl,
)
from ..encoding.tlv_model import tlv_encode, tlv_parse
from ..encoding.ndn_format_0_3 import (
    ContentType,
    DataPacketValue,
    MetaInfo,
    SignatureInfo,
    TypeNumber,
    write_signature_info,
)


KEY_COMPONENT = Component.from_str('KEY')
SELF_COMPONENT = Component.from_str('self')
SIGN_REQ_COMPONENT = Component.from_str('cert-request')


class SecurityV2TypeNumber:
    VALIDITY_PERIOD = 0xFD
    NOT_BEFORE = 0xFE
    NOT_AFTER = 0xFF
    ADDITIONAL_DESCRIPTION = 0x0102
    DESCRIPTION_ENTRY = 0x0200
    DESCRIPTION_KEY = 0x0201
    DESCRIPTION_VALUE = 0x0202

    SAFE_BAG = 0x80
    ENCRYPTED_KEY_BAG = 0x81


@dc.dataclass
class DescriptionEntry:
    description_key: bytes | None = dc.field(
        default=None, metadata={
            'tlv_type': SecurityV2TypeNumber.DESCRIPTION_KEY})
    description_value: bytes | None = dc.field(
        default=None, metadata={
            'tlv_type': SecurityV2TypeNumber.DESCRIPTION_VALUE})


@dc.dataclass
class AdditionalDescription:
    description_entry: list[DescriptionEntry] = dc.field(
        default_factory=list, metadata={
            'tlv_type': SecurityV2TypeNumber.DESCRIPTION_ENTRY})


@dc.dataclass
class CertificateV2Extension:
    additional_description: AdditionalDescription | None = dc.field(
        default=None, metadata={
            'tlv_type': SecurityV2TypeNumber.ADDITIONAL_DESCRIPTION})


@dc.dataclass
class ValidityPeriod:
    not_before: bytes | None = dc.field(
        default=None, metadata={'tlv_type': SecurityV2TypeNumber.NOT_BEFORE})
    not_after: bytes | None = dc.field(
        default=None, metadata={'tlv_type': SecurityV2TypeNumber.NOT_AFTER})


@dc.dataclass
class CertificateV2SignatureInfo(SignatureInfo):
    validity_period: ValidityPeriod | None = dc.field(
        default=None, metadata={
            'tlv_type': SecurityV2TypeNumber.VALIDITY_PERIOD})
    additional_description: AdditionalDescription | None = dc.field(
        default=None, metadata={
            'tlv_type': SecurityV2TypeNumber.ADDITIONAL_DESCRIPTION})


@dc.dataclass
class CertificateV2Value(DataPacketValue):
    signature_info: CertificateV2SignatureInfo | None = dc.field(
        default=None, metadata={
            'tlv_type': TypeNumber.SIGNATURE_INFO,
            'ignore_critical': True,
        })


@dc.dataclass
class SafeBag:
    certificate_v2: bytes | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.DATA})
    # Keep the certificate as encoded bytes instead of a nested dataclass:
    # 1. The encoded length of CertificateV2 is unknown.
    # 2. Generally we already have an encoded certificate when exporting a
    #    SafeBag.
    encrypted_key_bag: bytes | None = dc.field(
        default=None, metadata={
            'tlv_type': SecurityV2TypeNumber.ENCRYPTED_KEY_BAG})


@dc.dataclass
class _CertificateEnvelope:
    value: bytes = dc.field(metadata={'tlv_type': TypeNumber.DATA})


def parse_certificate(wire) -> CertificateV2Value:
    wire = parse_and_check_tl(wire, TypeNumber.DATA)
    return tlv_parse(CertificateV2Value, wire)


def new_cert(key_name, issuer_id_component, pub_key, signer,
             start_time, end_time) -> tuple[FormalName, VarBinaryStr]:
    cert_name = Name.normalize(key_name) + [
        issuer_id_component,
        Component.from_version(timestamp()),
    ]
    not_before = start_time.strftime('%Y%m%dT%H%M%S').encode()
    not_after = end_time.strftime('%Y%m%dT%H%M%S').encode()
    signature_info = CertificateV2SignatureInfo(
        validity_period=ValidityPeriod(
            not_before=not_before,
            not_after=not_after,
        ),
    )
    write_signature_info(signer, signature_info)
    cert_val = CertificateV2Value(
        name=cert_name,
        content=pub_key,
        meta_info=MetaInfo(
            content_type=ContentType.KEY,
            freshness_period=3600000,
        ),
        signature_info=signature_info,
    )
    value = tlv_encode(cert_val, markers={'##signer': signer})
    return cert_name, tlv_encode(_CertificateEnvelope(value=value))


def self_sign(key_name, pub_key, signer) -> tuple[FormalName, VarBinaryStr]:
    end_time = datetime.now(UTC)
    end_time = end_time.replace(year=end_time.year + 20)
    return new_cert(key_name, SELF_COMPONENT, pub_key, signer,
                    datetime.fromisoformat('1970-01-01T00:00:00'), end_time)


def sign_req(key_name, pub_key, signer) -> tuple[FormalName, VarBinaryStr]:
    start_time = datetime.now(UTC)
    end_time = start_time + timedelta(days=10)
    return new_cert(key_name, SIGN_REQ_COMPONENT, pub_key, signer,
                    datetime.now(UTC), end_time)


def derive_cert(key_name, issuer_id, pub_key, signer,
                start_time, expire_sec) -> tuple[FormalName, VarBinaryStr]:
    end_time = start_time + timedelta(seconds=expire_sec)
    if isinstance(issuer_id, str):
        issuer_id = Component.from_str(issuer_id)
    return new_cert(key_name, issuer_id, pub_key, signer, start_time, end_time)
