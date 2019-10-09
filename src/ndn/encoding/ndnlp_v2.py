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
from .tlv_type import BinaryStr
from .tlv_var import parse_and_check_tl
from .tlv_model import TlvModel, UintField, BytesField, ModelField


__all__ = ['LpTypeNumber', 'NackReason', 'parse_network_nack']


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


def parse_network_nack(wire: BinaryStr, with_tl: bool = True) -> (Optional[int], Optional[BinaryStr]):
    if with_tl:
        wire = parse_and_check_tl(wire, LpTypeNumber.LP_PACKET)
    markers = {}
    ret = LpPacketValue.parse(wire, markers, ignore_critical=True)

    if ret.nack is not None:
        return ret.nack.nack_reason, ret.fragment
    else:
        return None, None
