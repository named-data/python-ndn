# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
# Licensed under the Apache License, Version 2.0 (the "License");
# -----------------------------------------------------------------------------
"""NDN Packet Format v0.3 models using the dataclass TLV API."""
import dataclasses as dc

from .name import Name, Component
from .signer import Signer
from .tlv_model import NDNName, tlv_encode, tlv_parse
from .tlv_type import BinaryStr, VarBinaryStr, NonStrictName, FormalName
from .tlv_var import get_tl_num_size, parse_and_check_tl, write_tl_num

__all__ = [
    'TypeNumber', 'ContentType', 'SignatureType', 'KeyLocator',
    'SignatureInfo', 'write_signature_info',
    'Links', 'MetaInfo', 'InterestParam', 'SignaturePtrs', 'make_interest',
    'make_data', 'parse_interest', 'parse_data', 'Interest', 'Data',
]


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
    SHA256_WITH_ECDSA = 3
    HMAC_WITH_SHA256 = 4
    ED25519 = 5
    NULL = 200


@dc.dataclass
class KeyLocator:
    name: NDNName = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.NAME})
    key_digest: bytes | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.KEY_DIGEST})


@dc.dataclass
class SignatureInfo:
    signature_type: int | None = dc.field(
        default=None, metadata={
            'tlv_type': TypeNumber.SIGNATURE_TYPE, 'fixed_len': 1})
    key_locator: KeyLocator | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.KEY_LOCATOR})
    signature_nonce: int | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.SIGNATURE_NONCE})
    signature_time: int | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.SIGNATURE_TIME})
    signature_seq_num: int | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.SIGNATURE_SEQ_NUM})


def write_signature_info(signer: Signer, signature_info: SignatureInfo) -> None:
    """
    Let *signer* fill *signature_info*.

    Signers still assign the v1 ``KeyLocator`` model, which the dataclass
    encoder cannot serialize, so it is converted to :class:`KeyLocator`.
    """
    signer.write_signature_info(signature_info)
    key_locator = signature_info.key_locator
    if key_locator is not None and not isinstance(key_locator, KeyLocator):
        signature_info.key_locator = KeyLocator(
            name=key_locator.name, key_digest=key_locator.key_digest)


@dc.dataclass
class Links:
    names: list[NDNName] = dc.field(
        default_factory=list, metadata={'tlv_type': TypeNumber.NAME})


@dc.dataclass
class InterestPacketValue:
    name: NDNName = dc.field(default='/', metadata={
        'tlv_type': TypeNumber.NAME, 'field_type': 'interest_name'})
    can_be_prefix: bool = dc.field(
        default=False, metadata={'tlv_type': TypeNumber.CAN_BE_PREFIX})
    must_be_fresh: bool = dc.field(
        default=False, metadata={'tlv_type': TypeNumber.MUST_BE_FRESH})
    forwarding_hint: Links | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.FORWARDING_HINT})
    nonce: int | None = dc.field(default=None, metadata={
        'tlv_type': TypeNumber.NONCE, 'fixed_len': 4})
    lifetime: int | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.INTEREST_LIFETIME})
    hop_limit: int | None = dc.field(default=None, metadata={
        'tlv_type': TypeNumber.HOP_LIMIT, 'fixed_len': 1})
    _sig_cover_start: None = dc.field(
        default=None, metadata={'field_type': 'offset_marker'})
    _digest_cover_start: None = dc.field(
        default=None, metadata={'field_type': 'offset_marker'})
    application_parameters: bytes | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.APPLICATION_PARAMETERS})
    signature_info: SignatureInfo | None = dc.field(
        default=None, metadata={
            'tlv_type': TypeNumber.INTEREST_SIGNATURE_INFO})
    signature_value: bytes | None = dc.field(default=None, metadata={
        'tlv_type': TypeNumber.INTEREST_SIGNATURE_VALUE,
        'field_type': 'sig_value',
        'cover_start': '_sig_cover_start',
        'digest_cover_start': '_digest_cover_start',
        'digest_cover_end': '_digest_cover_end',
    })
    _digest_cover_end: None = dc.field(
        default=None, metadata={'field_type': 'offset_marker'})


@dc.dataclass
class InterestPacket:
    interest: InterestPacketValue | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.INTEREST})


@dc.dataclass(init=False)
class MetaInfo:
    content_type: int | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.CONTENT_TYPE})
    freshness_period: int | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.FRESHNESS_PERIOD})
    final_block_id: bytes | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.FINAL_BLOCK_ID})

    def __init__(self,
                 content_type: int | None = ContentType.BLOB,
                 freshness_period: int | None = None,
                 final_block_id: BinaryStr | None = None):
        self.content_type = content_type
        self.freshness_period = freshness_period
        self.final_block_id = final_block_id

    @staticmethod
    def from_dict(kwargs):
        return MetaInfo(**{
            f.name: kwargs[f.name]
            for f in dc.fields(MetaInfo)
            if f.name in kwargs
        })


@dc.dataclass
class DataPacketValue:
    _sig_cover_start: None = dc.field(
        default=None, metadata={'field_type': 'offset_marker'})
    name: NDNName = dc.field(
        default='/', metadata={'tlv_type': TypeNumber.NAME})
    meta_info: MetaInfo | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.META_INFO})
    content: bytes | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.CONTENT})
    signature_info: SignatureInfo | None = dc.field(default=None, metadata={
        'tlv_type': TypeNumber.SIGNATURE_INFO, 'ignore_critical': True})
    signature_value: bytes | None = dc.field(default=None, metadata={
        'tlv_type': TypeNumber.SIGNATURE_VALUE,
        'field_type': 'sig_value',
        'cover_start': '_sig_cover_start',
    })


@dc.dataclass
class DataPacket:
    data: DataPacketValue | None = dc.field(
        default=None, metadata={'tlv_type': TypeNumber.DATA})


@dc.dataclass
class InterestParam:
    can_be_prefix: bool = False
    must_be_fresh: bool = False
    nonce: int | None = None
    lifetime: int | None = 4000
    hop_limit: int | None = None
    forwarding_hint: list[NonStrictName] = dc.field(default_factory=list)

    @staticmethod
    def from_dict(kwargs):
        return InterestParam(**{
            f.name: kwargs[f.name]
            for f in dc.fields(InterestParam)
            if f.name in kwargs
        })


@dc.dataclass
class SignaturePtrs:
    signature_info: SignatureInfo | None = None
    signature_covered_part: list[BinaryStr] = dc.field(default_factory=list)
    signature_value_buf: BinaryStr | None = None
    digest_covered_part: list[BinaryStr] = dc.field(default_factory=list)
    digest_value_buf: BinaryStr | None = None


Interest = tuple[FormalName, InterestParam, BinaryStr | None, SignaturePtrs]
Data = tuple[FormalName, MetaInfo, BinaryStr | None, SignaturePtrs]


def _wrap_tlv(type_num: int, value: BinaryStr) -> VarBinaryStr:
    total = (
        get_tl_num_size(type_num)
        + get_tl_num_size(len(value))
        + len(value)
    )
    wire = bytearray(total)
    offset = write_tl_num(type_num, wire, 0)
    offset += write_tl_num(len(value), wire, offset)
    wire[offset:] = value
    return wire


def make_interest(name: NonStrictName,
                  interest_param: InterestParam,
                  app_param: BinaryStr | None = None,
                  signer: Signer | None = None,
                  need_final_name: bool = False):
    value = InterestPacketValue(
        name=name,
        can_be_prefix=interest_param.can_be_prefix,
        must_be_fresh=interest_param.must_be_fresh,
        nonce=interest_param.nonce,
        lifetime=interest_param.lifetime,
        hop_limit=interest_param.hop_limit,
        application_parameters=app_param,
    )
    if interest_param.forwarding_hint:
        value.forwarding_hint = Links(
            names=list(interest_param.forwarding_hint))
    if signer is not None:
        value.signature_info = SignatureInfo()
        write_signature_info(signer, value.signature_info)
        if value.application_parameters is None:
            value.application_parameters = b''

    markers = {
        '##signer': signer,
        '##need_digest': value.application_parameters is not None,
        '##_digest_cover_start_field': '_digest_cover_start',
        '##_digest_cover_end_field': '_digest_cover_end',
    }
    encoded_value = tlv_encode(value, markers=markers)
    wire = _wrap_tlv(TypeNumber.INTEREST, encoded_value)
    if need_final_name:
        final_value = tlv_parse(InterestPacketValue, encoded_value)
        return wire, final_value.name
    return wire


def make_data(name: NonStrictName,
              meta_info: MetaInfo,
              content: BinaryStr | None = None,
              signer: Signer | None = None) -> VarBinaryStr:
    value = DataPacketValue(name=name, meta_info=meta_info, content=content)
    if signer is not None:
        value.signature_info = SignatureInfo()
        write_signature_info(signer, value.signature_info)
    encoded_value = tlv_encode(value, markers={'##signer': signer})
    return _wrap_tlv(TypeNumber.DATA, encoded_value)


def parse_interest(wire: BinaryStr, with_tl: bool = True) -> Interest:
    value_wire = (
        parse_and_check_tl(wire, TypeNumber.INTEREST)
        if with_tl else wire
    )
    markers = {}
    ret = tlv_parse(InterestPacketValue, value_wire, markers=markers)
    params = InterestParam(
        can_be_prefix=ret.can_be_prefix,
        must_be_fresh=ret.must_be_fresh,
        nonce=ret.nonce,
        lifetime=ret.lifetime,
        hop_limit=ret.hop_limit,
    )
    if ret.forwarding_hint:
        params.forwarding_hint.extend(ret.forwarding_hint.names)

    digest_parts = []
    digest_start = markers.get('_digest_cover_start')
    if digest_start is not None:
        digest_parts.append(memoryview(value_wire)[digest_start:])
    sig_ptrs = SignaturePtrs(
        signature_info=ret.signature_info,
        signature_covered_part=markers.get('##sig_covered_part', []),
        signature_value_buf=ret.signature_value,
        digest_covered_part=digest_parts,
        digest_value_buf=markers.get('##digest_buf'),
    )
    return ret.name, params, ret.application_parameters, sig_ptrs


def parse_data(wire: BinaryStr, with_tl: bool = True) -> Data:
    value_wire = parse_and_check_tl(wire, TypeNumber.DATA) if with_tl else wire
    markers = {}
    ret = tlv_parse(DataPacketValue, value_wire, markers=markers)
    meta_info = ret.meta_info if ret.meta_info is not None else MetaInfo()
    sig_ptrs = SignaturePtrs(
        signature_info=ret.signature_info,
        signature_covered_part=markers.get('##sig_covered_part', []),
        signature_value_buf=ret.signature_value,
    )
    return ret.name, meta_info, ret.content, sig_ptrs
