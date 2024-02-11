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
import struct
from enum import Enum, Flag
from typing import Optional
from ..transport.face import Face
from ..utils import timestamp, gen_nonce_64
from ..encoding import Component, Name, ModelField, TlvModel, NameField, UintField, BytesField, \
    SignatureInfo, get_tl_num_size, TypeNumber, write_tl_num, parse_and_check_tl, \
    RepeatedField
from ..security import DigestSha256Signer


class FaceScope(Enum):
    NON_LOCAL = 0
    LOCAL = 1


class FacePersistency(Enum):
    PERSISTENT = 0
    ON_DEMAND = 1
    PERMANENT = 2


class FaceLinkType(Enum):
    POINT_TO_POINT = 0
    MULTI_ACCESS = 1
    AD_HOC = 2


class FaceFlags(Flag):
    NO_FLAG = 0
    LOCAL_FIELDS_ENABLED = 1
    LP_RELIABILITY_ENABLED = 2
    CONGESTION_MARKING_ENABLED = 4


class RouteFlags(Flag):
    NO_FLAG = 0
    CHILD_INHERIT = 1
    CAPTURE = 2


class FaceEventKind(Enum):
    CREATED = 1
    DESTROYED = 2
    UP = 3
    DOWN = 4


class Strategy(TlvModel):
    name = NameField()


class ControlParametersValue(TlvModel):
    name = NameField()
    face_id = UintField(0x69)
    uri = BytesField(0x72, is_string=True)
    local_uri = BytesField(0x81, is_string=True)
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
    face_persistency = UintField(0x85, val_base_type=FacePersistency)


class ControlParameters(TlvModel):
    cp = ModelField(0x68, ControlParametersValue)


class ControlResponse(TlvModel):
    status_code = UintField(0x66)
    status_text = BytesField(0x67, is_string=True)
    body = ModelField(0x68, ControlParametersValue)


class FaceEventNotificationValue(TlvModel):
    face_event_kind = UintField(0xc1, val_base_type=FaceEventKind)
    face_id = UintField(0x69)
    uri = BytesField(0x72, is_string=True)
    local_uri = BytesField(0x81, is_string=True)
    face_scope = UintField(0x84, val_base_type=FaceScope)
    face_persistency = UintField(0x85, val_base_type=FacePersistency)
    link_type = UintField(0x86, val_base_type=FaceLinkType)
    flags = UintField(0x6c, val_base_type=FaceFlags)


class FaceEventNotification(TlvModel):
    event = ModelField(0xc0, FaceEventNotificationValue)


class GeneralStatus(TlvModel):
    nfd_version = BytesField(0x80, is_string=True)
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
    # The following comes from DNMP's extension to NFD mgmt protocol:
    # https://github.com/pollere/DNMP-v2/blob/c4359ae1af03824ec1ee8cd27a7d52c9151fa813/formats/forwarder-status.proto
    # It does not show up in the standard protocol:
    # https://redmine.named-data.net/projects/nfd/wiki/ForwarderStatus
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
    uri = BytesField(0x72, is_string=True)
    local_uri = BytesField(0x81, is_string=True)
    expiration_period = UintField(0x6d)
    face_scope = UintField(0x84, val_base_type=FaceScope)
    face_persistency = UintField(0x85, val_base_type=FacePersistency)
    link_type = UintField(0x86, val_base_type=FaceLinkType)
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
    flags = UintField(0x6c, val_base_type=FaceFlags)


class FaceStatusMsg(TlvModel):
    face_status = RepeatedField(ModelField(0x80, FaceStatus))


class FaceQueryFilterValue(TlvModel):
    face_id = UintField(0x69)
    uri_scheme = BytesField(0x83, is_string=True)
    uri = BytesField(0x72, is_string=True)
    local_uri = BytesField(0x81, is_string=True)
    face_scope = UintField(0x84, val_base_type=FaceScope)
    face_persistency = UintField(0x85, val_base_type=FacePersistency)
    link_type = UintField(0x86, val_base_type=FaceLinkType)


class FaceQueryFilter(TlvModel):
    face_query_filter = ModelField(0x96, FaceQueryFilterValue)


class Route(TlvModel):
    face_id = UintField(0x69)
    origin = UintField(0x6f)
    cost = UintField(0x6a)
    flags = UintField(0x6c, val_base_type=RouteFlags)
    expiration_period = UintField(0x6d)


class RibEntry(TlvModel):
    name = NameField()
    routes = RepeatedField(ModelField(0x81, Route))


class RibStatus(TlvModel):
    entries = RepeatedField(ModelField(0x80, RibEntry))


class NextHopRecord(TlvModel):
    face_id = UintField(0x69)
    cost = UintField(0x6a)


class FibEntry(TlvModel):
    name = NameField()
    next_hop_records = RepeatedField(ModelField(0x81, NextHopRecord))


class FibStatus(TlvModel):
    entries = RepeatedField(ModelField(0x80, FibEntry))


class StrategyChoice(TlvModel):
    name = NameField()
    strategy = ModelField(0x6b, Strategy)


class StrategyChoiceMsg(TlvModel):
    strategy_choices = RepeatedField(ModelField(0x80, StrategyChoice))


class CsInfo(TlvModel):
    capacity = UintField(0x83)
    flags = UintField(0x6c)
    n_cs_entries = UintField(0x87)
    n_hits = UintField(0x81)
    n_misses = UintField(0x82)


def make_command(module, command, face: Optional[Face] = None, **kwargs):
    ret = make_command_v2(module, command, face, **kwargs)

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


def make_command_v2(module, command, face: Optional[Face] = None, **kwargs):
    # V2 returns the Command Interest name for the NDNv3 signed Interest
    # Note: this behavior is supported by NFD and YaNFD but has not been documented yet (on 06/26/2022):
    # https://redmine.named-data.net/projects/nfd/wiki/ControlCommand
    # Add ``app_param=b'', signer=sec.DigestSha256Signer(for_interest=True)`` to app.express when using this.
    local = face.isLocalFace() if face else True

    if local:
        ret = Name.from_str(f"/localhost/nfd/{module}/{command}")
    else:
        ret = Name.from_str(f"/localhop/nfd/{module}/{command}")
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
    return ret


def parse_response(buf):
    buf = parse_and_check_tl(memoryview(buf), 0x65)
    cr = ControlResponse.parse(buf)
    ret = {}
    ret['status_code'] = cr.status_code
    ret['status_text'] = cr.status_text
    params = cr.body
    for k in ControlParametersValue._encoded_fields:
        val = getattr(params, k.name)
        if isinstance(val, memoryview):
            val = bytes(val)
        ret[k.name] = val
    return ret
