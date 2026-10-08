# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
# Licensed under the Apache License, Version 2.0 (the "License");
# -----------------------------------------------------------------------------
"""NDNLPv2 models using the dataclass TLV API."""
import dataclasses as dc

from .tlv_model import DecodeError
from .tlv_model import tlv_encode, tlv_parse
from .tlv_type import BinaryStr, VarBinaryStr
from .tlv_var import parse_and_check_tl

__all__ = [
    'LpTypeNumber', 'NackReason', 'NetworkNack', 'CachePolicy',
    'LpPacketValue', 'LpPacket', 'parse_network_nack', 'make_network_nack',
    'parse_lp_packet', 'parse_lp_packet_v2',
]


class LpTypeNumber:
    FRAGMENT = 0x50
    SEQUENCE = 0x51
    FRAG_INDEX = 0x52
    FRAG_COUNT = 0x53
    HOP_COUNT = 0x54
    PIT_TOKEN = 0x62
    LP_PACKET = 0x64
    NACK = 0x0320
    NACK_REASON = 0x0321
    INCOMING_FACE_ID = 0x032C
    NEXT_HOP_FACE_ID = 0x0330
    CACHE_POLICY = 0x0334
    CACHE_POLICY_TYPE = 0x0335
    CONGESTION_MARK = 0x0340
    ACK = 0x0344
    TX_SEQUENCE = 0x0348
    NON_DISCOVERY = 0x034C
    PREFIX_ANNOUNCEMENT = 0x0350


class NackReason:
    NONE = 0
    CONGESTION = 50
    DUPLICATE = 100
    NO_ROUTE = 150


@dc.dataclass
class NetworkNack:
    nack_reason: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.NACK_REASON})


@dc.dataclass
class CachePolicy:
    cache_policy_type: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.CACHE_POLICY_TYPE})


@dc.dataclass
class LpPacketValue:
    frag_index: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.FRAG_INDEX})
    frag_count: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.FRAG_COUNT})
    pit_token: bytes | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.PIT_TOKEN})
    nack: NetworkNack | None = dc.field(
        default=None, metadata={
            'tlv_type': LpTypeNumber.NACK, 'ignore_critical': False})
    incoming_face_id: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.INCOMING_FACE_ID})
    next_hop_face_id: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.NEXT_HOP_FACE_ID})
    cache_policy: CachePolicy | None = dc.field(
        default=None, metadata={
            'tlv_type': LpTypeNumber.CACHE_POLICY, 'ignore_critical': False})
    congestion_mark: int | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.CONGESTION_MARK})
    tx_sequence: bytes | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.TX_SEQUENCE})
    ack: bytes | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.ACK})
    non_discovery: bool = dc.field(
        default=False, metadata={'tlv_type': LpTypeNumber.NON_DISCOVERY})
    prefix_announcement: bytes | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.PREFIX_ANNOUNCEMENT})
    fragment: bytes | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.FRAGMENT})


@dc.dataclass
class LpPacket:
    lp_packet: LpPacketValue | None = dc.field(
        default=None, metadata={'tlv_type': LpTypeNumber.LP_PACKET})


def parse_lp_packet(wire: BinaryStr,
                    with_tl: bool = True
                    ) -> tuple[int | None, BinaryStr | None]:
    ret = parse_lp_packet_v2(wire, with_tl)
    reason = ret.nack.nack_reason if ret.nack is not None else None
    return reason, ret.fragment


def parse_lp_packet_v2(wire: BinaryStr, with_tl: bool = True) -> LpPacketValue:
    if with_tl:
        wire = parse_and_check_tl(wire, LpTypeNumber.LP_PACKET)
    ret = tlv_parse(LpPacketValue, wire, ignore_critical=True)
    if ret.frag_index is not None or ret.frag_count is not None:
        raise DecodeError('NDNLP fragmentation is not implemented yet.')
    return ret


def parse_network_nack(
        wire: BinaryStr,
        with_tl: bool = True) -> tuple[int | None, BinaryStr | None]:
    if with_tl:
        wire = parse_and_check_tl(wire, LpTypeNumber.LP_PACKET)
    ret = tlv_parse(LpPacketValue, wire, ignore_critical=True)
    if ret.nack is not None:
        return ret.nack.nack_reason, ret.fragment
    return None, None


def make_network_nack(encoded_interest: BinaryStr,
                      nack_reason: int) -> VarBinaryStr:
    value = LpPacketValue(
        nack=NetworkNack(nack_reason=nack_reason),
        fragment=encoded_interest,
    )
    return tlv_encode(LpPacket(lp_packet=value))
