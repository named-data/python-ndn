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
from typing import Optional
from .tlv_type import BinaryStr, VarBinaryStr
from .tlv_var import parse_and_check_tl
from .tlv_model import TlvModel, UintField, BytesField, ModelField, BoolField, DecodeError

__all__ = ['LpTypeNumber', 'NackReason', 'parse_network_nack', 'make_network_nack', 'parse_lp_packet',
           'parse_lp_packet_v2']


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


class NetworkNack(TlvModel):
    nack_reason = UintField(LpTypeNumber.NACK_REASON)


class CachePolicy(TlvModel):
    cache_policy_type = UintField(LpTypeNumber.CACHE_POLICY_TYPE)


class LpPacketValue(TlvModel):
    frag_index = UintField(LpTypeNumber.FRAG_INDEX)
    frag_count = UintField(LpTypeNumber.FRAG_COUNT)
    pit_token = BytesField(LpTypeNumber.PIT_TOKEN)
    nack = ModelField(LpTypeNumber.NACK, NetworkNack)
    incoming_face_id = UintField(LpTypeNumber.INCOMING_FACE_ID)
    next_hop_face_id = UintField(LpTypeNumber.NEXT_HOP_FACE_ID)
    cache_policy = ModelField(LpTypeNumber.CACHE_POLICY, CachePolicy)
    congestion_mark = UintField(LpTypeNumber.CONGESTION_MARK)
    tx_sequence = BytesField(LpTypeNumber.TX_SEQUENCE)
    ack = BytesField(LpTypeNumber.ACK)
    non_discovery = BoolField(LpTypeNumber.NON_DISCOVERY)
    prefix_announcement = BytesField(LpTypeNumber.PREFIX_ANNOUNCEMENT)

    fragment = BytesField(LpTypeNumber.FRAGMENT)


class LpPacket(TlvModel):
    lp_packet = ModelField(LpTypeNumber.LP_PACKET, LpPacketValue)


def parse_lp_packet(wire: BinaryStr, with_tl: bool = True) -> (Optional[int], Optional[BinaryStr]):
    """
    Parse an LpPacket, return NackReason (if exists) and the fragment.

    :param wire: an LpPacket.
    :param with_tl: if `wire` has the TL fields.
    :return: a tuple of NackReason and Fragment.
    """
    ret = parse_lp_packet_v2(wire, with_tl)
    if ret.nack is not None:
        return ret.nack.nack_reason, ret.fragment
    else:
        return None, ret.fragment


def parse_lp_packet_v2(wire: BinaryStr, with_tl: bool = True) -> LpPacketValue:
    """
    Parse an LpPacket, return NackReason (if exists) and the fragment.

    :param wire: an LpPacket.
    :param with_tl: if `wire` has the TL fields.
    :return: LpPacketValue.
    """
    if with_tl:
        wire = parse_and_check_tl(wire, LpTypeNumber.LP_PACKET)
    markers = {}
    ret = LpPacketValue.parse(wire, markers, ignore_critical=True)

    if ret.frag_index is not None or ret.frag_count is not None:
        raise DecodeError('NDNLP fragmentation is not implemented yet.')

    return ret


def parse_network_nack(wire: BinaryStr, with_tl: bool = True) -> (Optional[int], Optional[BinaryStr]):
    if with_tl:
        wire = parse_and_check_tl(wire, LpTypeNumber.LP_PACKET)
    markers = {}
    ret = LpPacketValue.parse(wire, markers, ignore_critical=True)

    if ret.nack is not None:
        return ret.nack.nack_reason, ret.fragment
    else:
        return None, None


def make_network_nack(encoded_interest: BinaryStr, nack_reason: int) -> VarBinaryStr:
    lp_packet = LpPacket()
    lp_packet.lp_packet = LpPacketValue()
    lp_packet.lp_packet.nack = NetworkNack()
    lp_packet.lp_packet.nack.nack_reason = nack_reason
    lp_packet.lp_packet.fragment = encoded_interest
    return lp_packet.encode()
