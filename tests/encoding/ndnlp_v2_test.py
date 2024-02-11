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
from ndn.encoding import parse_network_nack, parse_interest, make_network_nack, make_interest, \
    NackReason, Name, InterestParam


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
