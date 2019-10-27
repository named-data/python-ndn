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
import struct
from ..utils import timestamp, gen_nonce_64
from ..encoding import Component, Name, ModelField, TlvModel, NameField, UintField, BytesField,\
    SignatureInfo, get_tl_num_size, TypeNumber, write_tl_num, IncludeBase, parse_and_check_tl,\
    RepeatedField
from ..security import DigestSha256Signer


class Strategy(TlvModel):
    name = NameField()


class ControlParametersValue(TlvModel):
    name = NameField()
    face_id = UintField(0x69)
    uri = BytesField(0x72)
    local_uri = BytesField(0x81)
    origin = UintField(0x6f)
    cost = UintField(0x6a)
    capacity = UintField(0x83)
    count = UintField(0x84)
    base_congestion_mark_interval = UintField(0x87)
    default_congestion_threshold = UintField(0x88)
    mtu = UintField(0x89)
    flags = UintField(0x6c)
    mask = UintField(0x70)
    strategy = ModelField(0x6b, Strategy)
    expiration_period = UintField(0x6d)
    face_persistency = UintField(0x85)


class ControlParameters(TlvModel):
    cp = ModelField(0x68, ControlParametersValue)


class ControlResponse(ControlParametersValue):
    status_code = UintField(0x66)
    status_text = BytesField(0x67)
    body = IncludeBase(ControlParametersValue)


class FaceEventNotificationValue(TlvModel):
    face_event_kind = UintField(0xc1)
    face_id = UintField(0x69)
    uri = BytesField(0x72)
    local_uri = BytesField(0x81)
    face_scope = UintField(0x84)
    face_persistency = UintField(0x85)
    link_type = UintField(0x86)
    flags = UintField(0x6c)


class FaceEventNotification(TlvModel):
    event = ModelField(0xc0, FaceEventNotificationValue)


class GeneralStatus(TlvModel):
    nfd_version = BytesField(0x80)
    start_timestamp = UintField(0x81)
    current_timestamp = UintField(0x82)
    n_name_tree_entries = UintField(0x83)
    n_fib_entries = UintField(0x84)
    n_pit_entries = UintField(0x85)
    n_measurement_entries = UintField(0x86)
    n_cs_entries = UintField(0x87)
    n_in_interests = UintField(0x90)
    n_in_data = UintField(0x91)
    n_in_nacks = UintField(0x97)
    n_out_interests = UintField(0x92)
    n_out_data = UintField(0x93)
    n_out_nacks = UintField(0x98)
    n_satisfied_interests = UintField(0x99)
    n_unsatisfied_interests = UintField(0x9a)
    n_fragmentation_errors = UintField(0xc8)
    n_out_over_mtu = UintField(0xc9)
    n_in_lp_invalid = UintField(0xca)
    n_reassembly_timeouts = UintField(0xcb)
    n_in_net_invalid = UintField(0xcc)
    n_acknowledged = UintField(0xcd)
    n_retransmitted = UintField(0xce)
    n_retx_exhausted = UintField(0xcf)
    n_congestion_marked = UintField(0xd0)


class FaceStatus(TlvModel):
    face_id = UintField(0x69)
    uri = BytesField(0x72)
    local_uri = BytesField(0x81)
    expiration_period = UintField(0x6d)
    face_scope = UintField(0x84)
    face_persistency = UintField(0x85)
    link_type = UintField(0x86)
    base_congestion_mark_interval = UintField(0x87)
    default_congestion_threshold = UintField(0x88)
    mtu = UintField(0x89)
    n_in_interests = UintField(0x90)
    n_in_data = UintField(0x91)
    n_in_nacks = UintField(0x97)
    n_out_interests = UintField(0x92)
    n_out_data = UintField(0x93)
    n_out_nacks = UintField(0x98)
    n_in_bytes = UintField(0x94)
    n_out_bytes = UintField(0x95)
    flags = UintField(0x6c)


class FaceStatusMsg(TlvModel):
    face_status = RepeatedField(ModelField(0x80, FaceStatus))


class FaceQueryFilterValue(TlvModel):
    face_id = UintField(0x69)
    uri_scheme = BytesField(0x83)
    uri = BytesField(0x72)
    local_uri = BytesField(0x81)
    face_scope = UintField(0x84)
    face_persistency = UintField(0x85)
    link_type = UintField(0x86)


class FaceQueryFilter(TlvModel):
    face_query_filter = ModelField(0x96, FaceQueryFilterValue)


class Route(TlvModel):
    face_id = UintField(0x69)
    origin = UintField(0x6f)
    cost = UintField(0x6a)
    flags = UintField(0x6c)
    expiration_period = UintField(0x6d)


class RibEntry(TlvModel):
    name = NameField()
    routes = RepeatedField(ModelField(0x81, Route))


class RibStatus(TlvModel):
    entries = RepeatedField(ModelField(0x80, RibEntry))


class StrategyChoice(TlvModel):
    name = NameField()
    strategy = ModelField(0x6b, Strategy)


class StrategyChoiceMsg(TlvModel):
    strategy_choices = RepeatedField(ModelField(0x80, StrategyChoice))


def make_command(module, command, **kwargs):
    ret = Name.from_str(f"/localhost/nfd/{module}/{command}")

    # Command parameters
    cp = ControlParameters()
    cp.cp = ControlParametersValue()
    for k, v in kwargs.items():
        if k == 'strategy':
            cp.cp.strategy = Strategy()
            cp.cp.strategy.name = v
        else:
            setattr(cp.cp, k, v)
    ret.append(Component.from_bytes(cp.encode()))

    # Timestamp and nonce
    ret.append(Component.from_bytes(struct.pack('!Q', timestamp())))
    ret.append(Component.from_bytes(struct.pack('!Q', gen_nonce_64())))

    # SignatureInfo
    signer = DigestSha256Signer()
    sig_info = SignatureInfo()
    signer.write_signature_info(sig_info)
    buf = sig_info.encode()
    ret.append(Component.from_bytes(bytes([TypeNumber.SIGNATURE_INFO, len(buf)]) + buf))

    # SignatureValue
    sig_size = signer.get_signature_value_size()
    tlv_length = 1 + get_tl_num_size(sig_size) + sig_size
    buf = bytearray(tlv_length)
    buf[0] = TypeNumber.SIGNATURE_VALUE
    offset = 1 + write_tl_num(sig_size, buf, 1)
    signer.write_signature_value(memoryview(buf)[offset:], ret)
    ret.append(Component.from_bytes(buf))

    return ret


def parse_response(buf):
    buf = parse_and_check_tl(memoryview(buf), 0x65)
    cr = ControlResponse.parse(buf)
    ret = {}
    for k in ControlResponse._encoded_fields:
        val = getattr(cr, k.name)
        if isinstance(val, memoryview):
            val = bytes(val)
        ret[k.name] = val
    return ret
