# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
from typing import Optional
from ..encoding import Component, Name, ModelField, TlvModel, NameField, UintField, BytesField,\
    SignatureInfo, TypeNumber, RepeatedField, IncludeBase, ProcedureArgument, OffsetMarker,\
    MetaInfo, VarBinaryStr
from ..encoding.tlv_model import SignatureValueField


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


class CertificateV2Value(TlvModel):
    _signer = ProcedureArgument()
    _sig_cover_part = ProcedureArgument()
    _sig_value_buf = ProcedureArgument()
    _shrink_len = ProcedureArgument()

    _sig_cover_start = OffsetMarker()
    name = NameField("/")
    meta_info = ModelField(TypeNumber.META_INFO, MetaInfo)
    content = BytesField(TypeNumber.CONTENT)
    # v0.2 Data packets has critical SignatureType-specific TLVs
    signature_info = ModelField(TypeNumber.SIGNATURE_INFO, CertificateV2SignatureInfo, ignore_critical=True)
    signature_value = SignatureValueField(TypeNumber.SIGNATURE_VALUE,
                                          signer=_signer,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf,
                                          shrink_len=_shrink_len)


def self_sign(key_name, pub_key, signer) -> VarBinaryStr:
    pass
