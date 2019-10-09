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
from ndn.encoding import parse_network_nack, parse_interest, NackReason, Name


class TestNetworkNack:
    @staticmethod
    def test1():
        lp_packet = (b'\xfd\x03 \x05\xfd\x03!\x01\x96'
                     b'P\x43\x05)\x07\x1f\x08\tlocalhost\x08\x03nfd\x08\x05faces\x08\x06events'
                     b'\x21\x00\x12\x00\x0c\x02\x03\xe8')
        nack_reason, interest = parse_network_nack(lp_packet, False)
        assert nack_reason == NackReason.NO_ROUTE
        name, param, _, _ = parse_interest(interest)
        assert name == Name.from_str("/localhost/nfd/faces/events")
        assert param.must_be_fresh
        assert param.can_be_prefix
        assert param.lifetime == 1000
