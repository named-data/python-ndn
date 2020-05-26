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
from typing import Optional
from .tlv_type import BinaryStr, VarBinaryStr, NonStrictName
from .tlv_var import parse_and_check_tl
from .tlv_model import TlvModel, UintField, BytesField, ModelField, NameField, BoolField
from .ndn_format_0_3 import InterestParam, TypeNumber, Links, Delegation


__all__ = ['LpTypeNumber', 'NackReason', 'parse_network_nack', 'make_network_nack']


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
    NEXT_HOP_FACE_ID = 0x0330
    INCOMING_FACE_ID = 0x0331
    CACHE_POLITY = 0x0334
    CACHE_POLITY_TYPE = 0x0335
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


class LpPacketValue(TlvModel):
    nack = ModelField(LpTypeNumber.NACK, NetworkNack)

    fragment = BytesField(LpTypeNumber.FRAGMENT)


class LpPacket(TlvModel):
    lp_packet = ModelField(LpTypeNumber.LP_PACKET, LpPacketValue)


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
