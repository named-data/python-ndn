# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 Xinyu Ma
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
from typing import Tuple
from datetime import datetime
from ..utils import timestamp
from ..encoding import Component, Name, ModelField, TlvModel, ContentType, BytesField,\
    SignatureInfo, TypeNumber, RepeatedField, IncludeBase, MetaInfo, VarBinaryStr,\
    get_tl_num_size, write_tl_num, parse_and_check_tl, FormalName
from ..encoding.ndn_format_0_3 import DataPacketValue


KEY_COMPONENT = Component.from_str('KEY')
SELF_COMPONENT = Component.from_str('self')


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


class DescriptionEntry(TlvModel):
    description_key = BytesField(SecurityV2TypeNumber.DESCRIPTION_KEY)
    description_value = BytesField(SecurityV2TypeNumber.DESCRIPTION_VALUE)


class AdditionalDescription(TlvModel):
    description_entry = RepeatedField(ModelField(SecurityV2TypeNumber.DESCRIPTION_ENTRY, DescriptionEntry))


class CertificateV2Extension(TlvModel):
    additional_description = ModelField(SecurityV2TypeNumber.ADDITIONAL_DESCRIPTION, AdditionalDescription)


class ValidityPeriod(TlvModel):
    not_before = BytesField(SecurityV2TypeNumber.NOT_BEFORE)
    not_after = BytesField(SecurityV2TypeNumber.NOT_AFTER)


class CertificateV2SignatureInfo(SignatureInfo, CertificateV2Extension):
    signature_info = IncludeBase(SignatureInfo)
    validity_period = ModelField(SecurityV2TypeNumber.VALIDITY_PERIOD, ValidityPeriod)
    certificate_v2_extension = IncludeBase(CertificateV2Extension)


class CertificateV2Value(DataPacketValue):
    _base = IncludeBase(DataPacketValue)
    signature_info = ModelField(TypeNumber.SIGNATURE_INFO, CertificateV2SignatureInfo, ignore_critical=True)


class SafeBag(TlvModel):
    certificate_v2 = BytesField(TypeNumber.DATA)
    # We do not use ModelField due to 2 reasons:
    # 1. The encoded length of CertificateV2 is unknown.
    # 2. Generally we already have an encoded certificate when exporting a SafeBag.
    encrypted_key_bag = BytesField(SecurityV2TypeNumber.ENCRYPTED_KEY_BAG)


def self_sign(key_name, pub_key, signer) -> Tuple[FormalName, VarBinaryStr]:
    cert_val = CertificateV2Value()
    cert_name = Name.normalize(key_name) + [SELF_COMPONENT, Component.from_version(timestamp())]
    cert_val.name = cert_name
    cert_val.content = pub_key
    cert_val.meta_info = MetaInfo(content_type=ContentType.KEY, freshness_period=3600000)
    cert_val.signature_info = CertificateV2SignatureInfo()
    cert_val.signature_info.validity_period = ValidityPeriod()
    cert_val.signature_info.validity_period.not_before = b'19700101T000000'
    end_time = datetime.utcnow()
    not_after = (f'{end_time.year+20:04}{end_time.month:02}{end_time.day:02}T'
                 f'{end_time.hour:02}{end_time.minute:02}{end_time.second:02}').encode()
    cert_val.signature_info.validity_period.not_after = not_after

    markers = {}
    cert_val._signer.set_arg(markers, signer)
    value = cert_val.encode(markers=markers)
    shrink_size = cert_val._shrink_len.get_arg(markers)
    type_len = get_tl_num_size(TypeNumber.DATA)
    size_len = get_tl_num_size(len(value) - shrink_size)
    buf = bytearray(type_len + size_len + len(value) - shrink_size)
    write_tl_num(TypeNumber.DATA, buf)
    write_tl_num(len(value) - shrink_size, buf, type_len)
    buf[type_len+size_len:] = memoryview(value)[0:len(value)-shrink_size]
    return cert_name, buf


def parse_certificate(wire) -> CertificateV2Value:
    wire = parse_and_check_tl(wire, TypeNumber.DATA)
    return CertificateV2Value.parse(wire)
