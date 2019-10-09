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
import dataclasses as dc
from hashlib import sha256
from typing import Optional, List, Tuple
from .name import Name, Component
from .signer import Signer
from .tlv_type import VarBinaryStr, BinaryStr, NonStrictName, FormalName
from .tlv_var import parse_and_check_tl
from .tlv_model import TlvModel, InterestNameField, BoolField, UintField, \
    SignatureValueField, OffsetMarker, BytesField, ModelField, NameField, \
    ProcedureArgument, RepeatedField


__all__ = ['TypeNumber', 'ContentType', 'SignatureType', 'KeyLocator', 'SignatureInfo', 'Delegation',
           'Links', 'InterestPacketValue', 'InterestPacket', 'MetaInfo', 'DataPacketValue', 'DataPacket',
           'InterestParam', 'SignaturePtrs', 'make_interest', 'make_data', 'parse_interest', 'parse_data',
           'Interest', 'Data']


class TypeNumber:
    INTEREST = 0x05
    DATA = 0x06

    NAME = Name.TYPE_NAME
    GENERIC_NAME_COMPONENT = Component.TYPE_GENERIC
    IMPLICIT_SHA256_DIGEST_COMPONENT = Component.TYPE_IMPLICIT_SHA256
    PARAMETERS_SHA256_DIGEST_COMPONENT = Component.TYPE_PARAMETERS_SHA256

    CAN_BE_PREFIX = 0x21
    MUST_BE_FRESH = 0x12
    FORWARDING_HINT = 0x1e
    NONCE = 0x0a
    INTEREST_LIFETIME = 0x0c
    HOP_LIMIT = 0x22
    APPLICATION_PARAMETERS = 0x24
    INTEREST_SIGNATURE_INFO = 0x2c
    INTEREST_SIGNATURE_VALUE = 0x2e

    META_INFO = 0x14
    CONTENT = 0x15
    SIGNATURE_INFO = 0x16
    SIGNATURE_VALUE = 0x17
    CONTENT_TYPE = 0x18
    FRESHNESS_PERIOD = 0x19
    FINAL_BLOCK_ID = 0x1a

    SIGNATURE_TYPE = 0x1b
    KEY_LOCATOR = 0x1c
    KEY_DIGEST = 0x1d
    SIGNATURE_NONCE = 0x26
    SIGNATURE_TIME = 0x28
    SIGNATURE_SEQ_NUM = 0x2a

    DELEGATION = 0x1f
    PREFERENCE = 0x1e


class ContentType:
    BLOB = 0
    LINK = 1
    KEY = 2
    NACK = 3


class SignatureType:
    NOT_SIGNED = None
    DIGEST_SHA256 = 0
    SHA256_WITH_RSA = 1
    SHA256_WITH_ECDSA = 2
    HMAC_WITH_SHA256 = 3


class KeyLocator(TlvModel):
    name = NameField()
    key_digest = BytesField(TypeNumber.KEY_DIGEST)


class SignatureInfo(TlvModel):
    signature_type = UintField(TypeNumber.SIGNATURE_TYPE, fixed_len=1)
    key_locator = ModelField(TypeNumber.KEY_LOCATOR, KeyLocator)
    signature_nonce = UintField(TypeNumber.SIGNATURE_NONCE)
    signature_time = UintField(TypeNumber.SIGNATURE_TIME)
    signature_seq_num = UintField(TypeNumber.SIGNATURE_SEQ_NUM)


class Delegation(TlvModel):
    preference = UintField(TypeNumber.PREFERENCE)
    delegation = NameField()


class Links(TlvModel):
    delegations = RepeatedField(ModelField(TypeNumber.DELEGATION, Delegation))


class InterestPacketValue(TlvModel):
    _signer = ProcedureArgument()
    _sig_cover_part = ProcedureArgument()
    _sig_value_buf = ProcedureArgument()
    _need_digest = ProcedureArgument()
    _digest_cover_part = ProcedureArgument()
    _digest_buf = ProcedureArgument()

    name = InterestNameField(need_digest=_need_digest,
                             signature_covered_part=_sig_cover_part,
                             digest_buffer=_digest_buf,
                             default="/")
    can_be_prefix = BoolField(TypeNumber.CAN_BE_PREFIX, default=False)
    must_be_fresh = BoolField(TypeNumber.MUST_BE_FRESH, default=False)
    forwarding_hint = ModelField(TypeNumber.FORWARDING_HINT, Links)
    nonce = UintField(TypeNumber.NONCE, fixed_len=4)
    lifetime = UintField(TypeNumber.INTEREST_LIFETIME)  # We can not write 4000 as a parse default
    hop_limit = UintField(TypeNumber.HOP_LIMIT, fixed_len=1)
    _sig_cover_start = OffsetMarker()
    _digest_cover_start = OffsetMarker()
    application_parameters = BytesField(TypeNumber.APPLICATION_PARAMETERS)
    signature_info = ModelField(TypeNumber.INTEREST_SIGNATURE_INFO, SignatureInfo)
    signature_value = SignatureValueField(TypeNumber.INTEREST_SIGNATURE_VALUE,
                                          interest_sig=True,
                                          signer=_signer,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf)
    _digest_cover_end = OffsetMarker()

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        self._sig_cover_part.set_arg(markers, [])

        signer = self._signer.get_arg(markers)
        if signer is not None:
            signer.write_signature_info(self.signature_info)
        app_param = self.application_parameters
        if (signer is not None) and (app_param is None):
            app_param = b''
            self.application_parameters = app_param

        self._need_digest.set_arg(markers, app_param is not None)

        return super().encoded_length(markers)

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        ret = super().encode(wire, offset, markers)
        wire_view = memoryview(ret)

        InterestPacketValue.signature_value.calculate_signature(markers)
        if self._need_digest.get_arg(markers):
            digest_cover_start = self._digest_cover_start.get_arg(markers)
            digest_cover_end = self._digest_cover_end.get_arg(markers)
            digest_covered_part = [wire_view[digest_cover_start:digest_cover_end]]
            self._digest_cover_part.set_arg(markers, digest_covered_part)
            sha256_algo = sha256()
            digest_buf = self._digest_buf.get_arg(markers)
            for blk in digest_covered_part:
                sha256_algo.update(blk)
            digest_buf[:] = sha256_algo.digest()

        return ret

    @classmethod
    def parse(cls, wire: BinaryStr, markers: Optional[dict] = None, ignore_critical: bool = False):
        if markers is None:
            markers = {}
        cls._sig_cover_part.set_arg(markers, [])
        ret = super().parse(wire, markers, ignore_critical)
        digest_cover_start = cls._digest_cover_start.get_arg(markers)
        digest_cover_end = cls._digest_cover_end.get_arg(markers)
        digest_cover_part = [memoryview(wire)[digest_cover_start:digest_cover_end]]
        cls._digest_cover_part.set_arg(markers, digest_cover_part)
        return ret


class InterestPacket(TlvModel):
    _signer = ProcedureArgument()
    interest = ModelField(TypeNumber.INTEREST, InterestPacketValue, [_signer])


class MetaInfo(TlvModel):
    content_type = UintField(TypeNumber.CONTENT_TYPE)
    freshness_period = UintField(TypeNumber.FRESHNESS_PERIOD)
    final_block_id = BytesField(TypeNumber.FINAL_BLOCK_ID)

    def __init__(self,
                 content_type: int = ContentType.BLOB,
                 freshness_period: Optional[int] = None,
                 final_block_id: BinaryStr = None):
        self.content_type = content_type
        self.freshness_period = freshness_period
        self.final_block_id = final_block_id

    @staticmethod
    def from_dict(kwargs):
        return MetaInfo(**{f.name: kwargs[f.name]
                           for f in MetaInfo._encoded_fields
                           if f.name in kwargs})


class DataPacketValue(TlvModel):
    _signer = ProcedureArgument()
    _sig_cover_part = ProcedureArgument()
    _sig_value_buf = ProcedureArgument()

    _sig_cover_start = OffsetMarker()
    name = NameField("/")
    meta_info = ModelField(TypeNumber.META_INFO, MetaInfo)
    content = BytesField(TypeNumber.CONTENT)
    # v0.2 Data packets has critical SignatureType-specific TLVs
    signature_info = ModelField(TypeNumber.SIGNATURE_INFO, SignatureInfo, ignore_critical=True)
    signature_value = SignatureValueField(TypeNumber.SIGNATURE_VALUE,
                                          interest_sig=True,
                                          signer=_signer,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf)

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        self._sig_cover_part.set_arg(markers, [])

        signer = self._signer.get_arg(markers)
        if signer is not None:
            signer.write_signature_info(self.signature_info)

        return super().encoded_length(markers)

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        ret = super().encode(wire, offset, markers)
        DataPacketValue.signature_value.calculate_signature(markers)
        return ret

    @classmethod
    def parse(cls, wire: BinaryStr, markers: Optional[dict] = None, ignore_critical: bool = False):
        if markers is None:
            markers = {}
        cls._sig_cover_part.set_arg(markers, [])
        return super().parse(wire, markers, ignore_critical)


class DataPacket(TlvModel):
    _signer = ProcedureArgument()
    data = ModelField(TypeNumber.DATA, DataPacketValue, [_signer])


@dc.dataclass
class InterestParam:
    can_be_prefix: bool = False
    must_be_fresh: bool = False
    nonce: Optional[int] = None
    lifetime: Optional[int] = 4000
    hop_limit: Optional[int] = None
    forwarding_hint: List[Tuple[int, NonStrictName]] = dc.field(default_factory=list)

    @staticmethod
    def from_dict(kwargs):
        return InterestParam(**{f.name: kwargs[f.name]
                                for f in dc.fields(InterestParam)
                                if f.name in kwargs})


@dc.dataclass
class SignaturePtrs:
    signature_info: Optional[SignatureInfo] = None
    signature_covered_part: Optional[List[BinaryStr]] = dc.field(default_factory=list)
    signature_value_buf: Optional[BinaryStr] = None
    digest_covered_part: Optional[List[BinaryStr]] = dc.field(default_factory=list)
    digest_value_buf: Optional[BinaryStr] = None


Interest = Tuple[FormalName, InterestParam, Optional[BinaryStr], SignaturePtrs]
Data = Tuple[FormalName, MetaInfo, Optional[BinaryStr], SignaturePtrs]


def make_interest(name: NonStrictName,
                  interest_param: InterestParam,
                  app_param: Optional[BinaryStr] = None,
                  signer: Signer = None,
                  need_final_name: bool = False):
    interest = InterestPacket()
    interest.interest = InterestPacketValue()
    interest.interest.name = name
    interest.interest.can_be_prefix = interest_param.can_be_prefix
    interest.interest.must_be_fresh = interest_param.must_be_fresh
    interest.interest.nonce = interest_param.nonce
    interest.interest.lifetime = interest_param.lifetime
    interest.interest.hop_limit = interest_param.hop_limit

    if interest_param.forwarding_hint:
        interest.interest.forwarding_hint = Links()
        for preference, delegation in interest_param.forwarding_hint:
            cur = Delegation()
            cur.preference = preference
            cur.delegation = delegation
            interest.interest.forwarding_hint.delegations.append(cur)

    interest.interest.application_parameters = app_param
    if signer is not None:
        interest.interest.signature_info = SignatureInfo()
    markers = {}
    interest._signer.set_arg(markers, signer)
    ret = interest.encode(markers=markers)
    if need_final_name:
        return ret, InterestPacketValue.name.get_final_name(markers['interest##inner_markers'])
    else:
        return ret


def make_data(name: NonStrictName,
              meta_info: MetaInfo,
              content: Optional[BinaryStr] = None,
              signer: Signer = None) -> bytearray:
    data = DataPacket()
    data.data = DataPacketValue()
    data.data.meta_info = meta_info
    data.data.name = name
    data.data.content = content
    if signer is not None:
        data.data.signature_info = SignatureInfo()
    markers = {}
    data._signer.set_arg(markers, signer)
    return data.encode(markers=markers)


def parse_interest(wire: BinaryStr, with_tl: bool = True) -> Interest:
    if with_tl:
        wire = parse_and_check_tl(wire, TypeNumber.INTEREST)
    markers = {}
    ret = InterestPacketValue.parse(wire, markers)
    params = InterestParam()
    params.can_be_prefix = ret.can_be_prefix
    params.must_be_fresh = ret.must_be_fresh
    params.nonce = ret.nonce
    params.lifetime = ret.lifetime
    params.hop_limit = ret.hop_limit

    if ret.forwarding_hint and ret.forwarding_hint.delegations:
        for cur in ret.forwarding_hint.delegations:
            params.forwarding_hint.append((cur.preference, cur.delegation))

    sig_ptrs = SignaturePtrs(
        signature_info=ret.signature_info,
        signature_covered_part=ret._sig_cover_part.get_arg(markers),
        signature_value_buf=ret.signature_value,
        digest_covered_part=ret._digest_cover_part.get_arg(markers),
        digest_value_buf=ret._digest_buf.get_arg(markers)
    )
    return ret.name, params, ret.application_parameters, sig_ptrs


def parse_data(wire: BinaryStr, with_tl: bool = True) -> Data:
    if with_tl:
        wire = parse_and_check_tl(wire, TypeNumber.DATA)
    markers = {}
    ret = DataPacketValue.parse(wire, markers)
    params = ret.meta_info
    sig_ptrs = SignaturePtrs(
        signature_info=ret.signature_info,
        signature_covered_part=ret._sig_cover_part.get_arg(markers),
        signature_value_buf=ret.signature_value,
    )
    return ret.name, params, ret.content, sig_ptrs
