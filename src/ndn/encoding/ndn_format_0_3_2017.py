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
from hashlib import sha256
from typing import Optional, List, Tuple
from .name import Name, Component
from .signer import Signer
from .tlv_type import VarBinaryStr, BinaryStr, NonStrictName, FormalName
from .tlv_var import parse_and_check_tl, shrink_length
from .tlv_model import TlvModel, InterestNameField, BoolField, UintField, \
    SignatureValueField, OffsetMarker, BytesField, ModelField, NameField, \
    ProcedureArgument, RepeatedField


__all__ = ['TypeNumber', 'ContentType', 'SignatureType', 'KeyLocator', 'SignatureInfo', 'Delegation',
           'Links', 'MetaInfo', 'InterestParam', 'SignaturePtrs', 'make_interest', 'make_data',
           'parse_interest', 'parse_data', 'Interest', 'Data']


class TypeNumber:
    r"""
    TLV Type numbers used in `NDN Packet Format 0.3
    <https://named-data.net/doc/NDN-packet-spec/current/types.html>`_.

    Constant names are changed to PEP 8 style, i.e., all upper cases with underscores separating words.
    """
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
    r"""
    Numbers used in ContentType.

    ====   ===================================
    Type   Description
    ====   ===================================
    BLOB   Payload identified by the data name
    LINK   A list of delegations
    KEY    Public Key
    NACK   Application-level NACK
    ====   ===================================
    """
    BLOB = 0
    LINK = 1
    KEY = 2
    NACK = 3


class SignatureType:
    r"""
    Numbers used in SignatureType.

    =================   ==================================================
    Type                Description
    =================   ==================================================
    NOT_SIGNED          Not signed
    DIGEST_SHA256       SHA-256 digest (only for integrity protection)
    SHA256_WITH_RSA     RSA signature over a SHA-256 digest
    SHA256_WITH_ECDSA   An ECDSA signature over a SHA-256 digest
    HMAC_WITH_SHA256    SHA256 hash-based message authentication codes
    NULL                An empty signature for testing and experimentation
    =================   ==================================================
    """
    NOT_SIGNED = None
    DIGEST_SHA256 = 0
    SHA256_WITH_RSA = 1
    SHA256_WITH_ECDSA = 3
    HMAC_WITH_SHA256 = 4
    NULL = 200


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
    _shrink_len = ProcedureArgument(0)

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
                                          signer=_signer,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf,
                                          shrink_len=_shrink_len)
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
            shrink_size = self._shrink_len.get_arg(markers)
            digest_cover_end = self._digest_cover_end.get_arg(markers) - shrink_size
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
    _shrink_len = ProcedureArgument(0)

    _sig_cover_start = OffsetMarker()
    name = NameField("/")
    meta_info = ModelField(TypeNumber.META_INFO, MetaInfo)
    content = BytesField(TypeNumber.CONTENT)
    # v0.2 Data packets has critical SignatureType-specific TLVs
    signature_info = ModelField(TypeNumber.SIGNATURE_INFO, SignatureInfo, ignore_critical=True)
    signature_value = SignatureValueField(TypeNumber.SIGNATURE_VALUE,
                                          signer=_signer,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf,
                                          shrink_len=_shrink_len)

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
    r"""
    A dataclass collecting the parameters of an Interest, except ApplicationParameters.

    :ivar can_be_prefix: CanBePrefix. ``False`` by default.
    :vartype can_be_prefix: bool

    :ivar must_be_fresh: MustBeFresh. ``False`` by default.
    :vartype must_be_fresh: bool

    :ivar nonce: Nonce. ``None`` by default.
    :vartype nonce: int

    :ivar lifetime: InterestLifetime in milliseconds. ``4000`` by default.
    :vartype lifetime: int

    :ivar hop_limit: HopLimit. ``None`` by default.
    :vartype hop_limit: int

    :ivar forwarding_hint: ForwardingHint. The type should be list of pairs of Preference and Name.
        e.g.: ``[(1, "/ndn/name1"), (2, ["ndn", "name2"])]``
    :vartype forwarding_hint: :class:`List` [ :class:`Tuple` [ :class:`int` , :any:`NonStrictName` ]]
    """
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
    r"""
    A set of pointers used to verify a packet.

    :ivar signature_info: the SignatureInfo.
    :vartype signature_info: :any:`SignatureInfo`

    :ivar signature_covered_part: a list of pointers, each of which points to a memory covered by signature.
    :vartype signature_covered_part: :class:`List` [ :class:`memoryview` ]

    :ivar signature_value_buf: a pointer to SignatureValue (TL excluded).
    :vartype signature_value_buf: :class:`memoryview`

    :ivar digest_covered_part: a list of pointers, each of which points to a memory covered by
        ParametersSha256DigestComponent.
    :vartype digest_covered_part: :class:`List` [ :class:`memoryview` ]

    :ivar digest_value_buf: a pointer to ParametersSha256DigestComponent (TL excluded).
    :vartype digest_value_buf: :class:`memoryview`
    """
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
                  signer: Optional[Signer] = None,
                  need_final_name: bool = False):
    r"""
    Make an Interest packet.

    :param name: the Name field.
    :type name: :any:`NonStrictName`
    :param interest_param: basic parameters of the Interest.
    :param app_param: the ApplicationParameters field.
    :type app_param: :class:`Optional` [ :any:`BinaryStr` ]
    :param signer: a Signer to sign this Interest. ``None`` if it is unsigned.
    :param need_final_name: if ``True``, also return the final Name with ParametersSha256DigestComponent.
    :return: TLV encoded Interest packet. If ``need_final_name``, return a tuple of the packet
        and the final Name.
    """
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
    shrink_size = interest.interest._shrink_len.get_arg(markers['interest##inner_markers'])
    if shrink_size > 0:
        ret = shrink_length(ret, shrink_size)
    if need_final_name:
        return ret, InterestPacketValue.name.get_final_name(markers['interest##inner_markers'])
    else:
        return ret


def make_data(name: NonStrictName,
              meta_info: MetaInfo,
              content: Optional[BinaryStr] = None,
              signer: Optional[Signer] = None) -> VarBinaryStr:
    r"""
    Make a Data packet.

    :param name: the Name field.
    :type name: :any:`NonStrictName`
    :param meta_info: the MetaIndo field.
    :param content: the Content.
    :type content: :class:`Optional` [ :any:`BinaryStr` ]
    :param signer: a Signer to sign this Interest. ``None`` if it is unsigned.
    :return: TLV encoded Data packet.
    """
    data = DataPacket()
    data.data = DataPacketValue()
    data.data.meta_info = meta_info
    data.data.name = name
    data.data.content = content
    if signer is not None:
        data.data.signature_info = SignatureInfo()
    markers = {}
    data._signer.set_arg(markers, signer)
    ret = data.encode(markers=markers)
    shrink_size = data.data._shrink_len.get_arg(markers['data##inner_markers'])
    if shrink_size > 0:
        ret = shrink_length(ret, shrink_size)
    return ret


def parse_interest(wire: BinaryStr, with_tl: bool = True) -> Interest:
    r"""
    Parse a TLV encoded Interest.

    :param wire: the buffer.
    :type wire: :any:`BinaryStr`
    :param with_tl: ``True`` if the packet has Type and Length.
        ``False`` if ``wire`` only has the Value part.
    :return: a Tuple of Name, InterestParameters, ApplicationParameters and :any:`SignaturePtrs`.
    :rtype: :class:`Tuple` [ :any:`FormalName` , :any:`InterestParam` ,
        :class:`Optional` [ :any:`BinaryStr` ], :any:`SignaturePtrs` ]
    """
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
    r"""
    Parse a TLV encoded Data.

    :param wire: the buffer.
    :type wire: :any:`BinaryStr`
    :param with_tl: ``True`` if the packet has Type and Length.
        ``False`` if ``wire`` only has the Value part.
    :return: a Tuple of Name, MetaInfo, Content and :any:`SignaturePtrs`.
    :rtype: :class:`Tuple` [ :any:`FormalName` , :any:`MetaInfo` ,
        :class:`Optional` [ :any:`BinaryStr` ], :any:`SignaturePtrs` ]
    """
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
