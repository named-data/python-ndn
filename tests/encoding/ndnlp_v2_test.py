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
import pytest
from ndn.encoding import (
    DecodeError,
    InterestParam,
    LpPacketValue,
    LpTypeNumber,
    NackReason,
    Name,
    NetworkNack,
    make_interest,
    make_network_nack,
    parse_interest,
    parse_lp_packet_v2,
    parse_network_nack,
    tlv_encode,
    write_tl_num,
)


class TestNetworkNack:
    @staticmethod
    def test1():
        lp_packet = (b"\x64\x32\xfd\x03\x20\x05\xfd\x03\x21\x01\x96"
                     b"\x50\x27\x05\x25\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events"
                     b"\x21\x00\x12\x00")
        nack_reason, interest = parse_network_nack(lp_packet, True)
        assert nack_reason == NackReason.NO_ROUTE
        name, param, _, _ = parse_interest(interest)
        assert name == Name.from_str("/localhost/nfd/faces/events")
        assert param.must_be_fresh
        assert param.can_be_prefix

    @staticmethod
    def test2():
        interest = make_interest('/localhost/nfd/faces/events',
                                 InterestParam(must_be_fresh=True, can_be_prefix=True))
        lp_packet = make_network_nack(interest, NackReason.NO_ROUTE)
        assert lp_packet == (b"\x64\x36\xfd\x03\x20\x05\xfd\x03\x21\x01\x96"
                             b"\x50\x2b\x05\x29\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events"
                             b"\x21\x00\x12\x00\x0c\x02\x0f\xa0")

def test_network_nack_wire_format():
    interest = make_interest(
        '/localhost/nfd/faces/events',
        InterestParam(must_be_fresh=True, can_be_prefix=True),
    )
    lp_packet = make_network_nack(interest, NackReason.NO_ROUTE)

    assert lp_packet == (
        b"\x64\x36\xfd\x03\x20\x05\xfd\x03\x21\x01\x96"
        b"\x50\x2b\x05\x29\x07\x1f\x08\tlocalhost\x08\x03nfd"
        b"\x08\x05faces\x08\x06events\x21\x00\x12\x00\x0c\x02\x0f\xa0"
    )

    reason, encoded_interest = parse_network_nack(lp_packet)
    name, params, _, _ = parse_interest(encoded_interest)
    assert reason == NackReason.NO_ROUTE
    assert name == Name.from_str('/localhost/nfd/faces/events')
    assert params.can_be_prefix
    assert params.must_be_fresh


def test_network_nack_parser_accepts_fragment_metadata():
    value = tlv_encode(LpPacketValue(
        frag_index=0,
        frag_count=1,
        nack=NetworkNack(nack_reason=NackReason.NO_ROUTE),
        fragment=b'\x05\x00',
    ))
    wire = bytearray(2 + len(value))
    offset = write_tl_num(LpTypeNumber.LP_PACKET, wire, 0)
    offset += write_tl_num(len(value), wire, offset)
    wire[offset:] = value

    assert parse_network_nack(wire) == (NackReason.NO_ROUTE, b'\x05\x00')


def test_nested_unknown_critical_field_is_rejected():
    wire = b'\x64\x06\xfd\x03\x20\x02\x01\x00'
    with pytest.raises(DecodeError):
        parse_lp_packet_v2(wire)
