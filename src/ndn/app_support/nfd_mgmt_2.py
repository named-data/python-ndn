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
"""NFD management protocol models using the dataclass TLV API."""
import dataclasses as dc
import struct
from typing import Optional

from ..transport.face import Face
from ..utils import timestamp, gen_nonce_64
from ..encoding import Component, Name, get_tl_num_size, write_tl_num, parse_and_check_tl
from ..encoding.tlv_model_v2 import NDNName, tlv_encode, tlv_parse
from ..encoding.ndn_format_0_3_2 import SignatureInfo, TypeNumber, write_signature_info
from ..security import DigestSha256Signer
from .nfd_mgmt import (
    FaceScope, FacePersistency, FaceLinkType, FaceFlags, RouteFlags, FaceEventKind,
)

__all__ = [
    'FaceScope', 'FacePersistency', 'FaceLinkType', 'FaceFlags', 'RouteFlags', 'FaceEventKind',
    'Strategy', 'ControlParametersValue', 'ControlParameters', 'ControlResponse',
    'FaceEventNotificationValue', 'FaceEventNotification', 'GeneralStatus', 'FaceStatus',
    'FaceStatusMsg', 'FaceQueryFilterValue', 'FaceQueryFilter', 'Route', 'RibEntry', 'RibStatus',
    'NextHopRecord', 'FibEntry', 'FibStatus', 'StrategyChoice', 'StrategyChoiceMsg', 'CsInfo',
    'make_command', 'make_command_v2', 'parse_response',
]


def _tlv(type_num: int):
    return dc.field(default=None, metadata={'tlv_type': type_num})


def _name():
    return _tlv(TypeNumber.NAME)


def _repeated(type_num: int):
    return dc.field(default_factory=list, metadata={'tlv_type': type_num})


@dc.dataclass
class Strategy:
    name: NDNName = _name()


@dc.dataclass
class ControlParametersValue:
    name: NDNName = _name()
    face_id: Optional[int] = _tlv(0x69)
    uri: Optional[str] = _tlv(0x72)
    local_uri: Optional[str] = _tlv(0x81)
    origin: Optional[int] = _tlv(0x6f)
    cost: Optional[int] = _tlv(0x6a)
    capacity: Optional[int] = _tlv(0x83)
    count: Optional[int] = _tlv(0x84)
    base_congestion_mark_interval: Optional[int] = _tlv(0x87)
    default_congestion_threshold: Optional[int] = _tlv(0x88)
    mtu: Optional[int] = _tlv(0x89)
    flags: Optional[int] = _tlv(0x6c)
    mask: Optional[int] = _tlv(0x70)
    strategy: Optional[Strategy] = _tlv(0x6b)
    expiration_period: Optional[int] = _tlv(0x6d)
    face_persistency: Optional[FacePersistency] = _tlv(0x85)


@dc.dataclass
class ControlParameters:
    cp: Optional[ControlParametersValue] = _tlv(0x68)


@dc.dataclass
class ControlResponse:
    status_code: Optional[int] = _tlv(0x66)
    status_text: Optional[str] = _tlv(0x67)
    body: Optional[ControlParametersValue] = _tlv(0x68)


@dc.dataclass
class FaceEventNotificationValue:
    face_event_kind: Optional[FaceEventKind] = _tlv(0xc1)
    face_id: Optional[int] = _tlv(0x69)
    uri: Optional[str] = _tlv(0x72)
    local_uri: Optional[str] = _tlv(0x81)
    face_scope: Optional[FaceScope] = _tlv(0x84)
    face_persistency: Optional[FacePersistency] = _tlv(0x85)
    link_type: Optional[FaceLinkType] = _tlv(0x86)
    flags: Optional[FaceFlags] = _tlv(0x6c)


@dc.dataclass
class FaceEventNotification:
    event: Optional[FaceEventNotificationValue] = _tlv(0xc0)


@dc.dataclass
class GeneralStatus:
    nfd_version: Optional[str] = _tlv(0x80)
    start_timestamp: Optional[int] = _tlv(0x81)
    current_timestamp: Optional[int] = _tlv(0x82)
    n_name_tree_entries: Optional[int] = _tlv(0x83)
    n_fib_entries: Optional[int] = _tlv(0x84)
    n_pit_entries: Optional[int] = _tlv(0x85)
    n_measurement_entries: Optional[int] = _tlv(0x86)
    n_cs_entries: Optional[int] = _tlv(0x87)
    n_in_interests: Optional[int] = _tlv(0x90)
    n_in_data: Optional[int] = _tlv(0x91)
    n_in_nacks: Optional[int] = _tlv(0x97)
    n_out_interests: Optional[int] = _tlv(0x92)
    n_out_data: Optional[int] = _tlv(0x93)
    n_out_nacks: Optional[int] = _tlv(0x98)
    n_satisfied_interests: Optional[int] = _tlv(0x99)
    n_unsatisfied_interests: Optional[int] = _tlv(0x9a)
    # The following comes from DNMP's extension to NFD mgmt protocol:
    # https://github.com/pollere/DNMP-v2/blob/c4359ae1af03824ec1ee8cd27a7d52c9151fa813/formats/forwarder-status.proto
    # It does not show up in the standard protocol:
    # https://redmine.named-data.net/projects/nfd/wiki/ForwarderStatus
    n_fragmentation_errors: Optional[int] = _tlv(0xc8)
    n_out_over_mtu: Optional[int] = _tlv(0xc9)
    n_in_lp_invalid: Optional[int] = _tlv(0xca)
    n_reassembly_timeouts: Optional[int] = _tlv(0xcb)
    n_in_net_invalid: Optional[int] = _tlv(0xcc)
    n_acknowledged: Optional[int] = _tlv(0xcd)
    n_retransmitted: Optional[int] = _tlv(0xce)
    n_retx_exhausted: Optional[int] = _tlv(0xcf)
    n_congestion_marked: Optional[int] = _tlv(0xd0)


@dc.dataclass
class FaceStatus:
    face_id: Optional[int] = _tlv(0x69)
    uri: Optional[str] = _tlv(0x72)
    local_uri: Optional[str] = _tlv(0x81)
    expiration_period: Optional[int] = _tlv(0x6d)
    face_scope: Optional[FaceScope] = _tlv(0x84)
    face_persistency: Optional[FacePersistency] = _tlv(0x85)
    link_type: Optional[FaceLinkType] = _tlv(0x86)
    base_congestion_mark_interval: Optional[int] = _tlv(0x87)
    default_congestion_threshold: Optional[int] = _tlv(0x88)
    mtu: Optional[int] = _tlv(0x89)
    n_in_interests: Optional[int] = _tlv(0x90)
    n_in_data: Optional[int] = _tlv(0x91)
    n_in_nacks: Optional[int] = _tlv(0x97)
    n_out_interests: Optional[int] = _tlv(0x92)
    n_out_data: Optional[int] = _tlv(0x93)
    n_out_nacks: Optional[int] = _tlv(0x98)
    n_in_bytes: Optional[int] = _tlv(0x94)
    n_out_bytes: Optional[int] = _tlv(0x95)
    flags: Optional[FaceFlags] = _tlv(0x6c)


@dc.dataclass
class FaceStatusMsg:
    face_status: list[FaceStatus] = _repeated(0x80)


@dc.dataclass
class FaceQueryFilterValue:
    face_id: Optional[int] = _tlv(0x69)
    uri_scheme: Optional[str] = _tlv(0x83)
    uri: Optional[str] = _tlv(0x72)
    local_uri: Optional[str] = _tlv(0x81)
    face_scope: Optional[FaceScope] = _tlv(0x84)
    face_persistency: Optional[FacePersistency] = _tlv(0x85)
    link_type: Optional[FaceLinkType] = _tlv(0x86)


@dc.dataclass
class FaceQueryFilter:
    face_query_filter: Optional[FaceQueryFilterValue] = _tlv(0x96)


@dc.dataclass
class Route:
    face_id: Optional[int] = _tlv(0x69)
    origin: Optional[int] = _tlv(0x6f)
    cost: Optional[int] = _tlv(0x6a)
    flags: Optional[RouteFlags] = _tlv(0x6c)
    expiration_period: Optional[int] = _tlv(0x6d)


@dc.dataclass
class RibEntry:
    name: NDNName = _name()
    routes: list[Route] = _repeated(0x81)


@dc.dataclass
class RibStatus:
    entries: list[RibEntry] = _repeated(0x80)


@dc.dataclass
class NextHopRecord:
    face_id: Optional[int] = _tlv(0x69)
    cost: Optional[int] = _tlv(0x6a)


@dc.dataclass
class FibEntry:
    name: NDNName = _name()
    next_hop_records: list[NextHopRecord] = _repeated(0x81)


@dc.dataclass
class FibStatus:
    entries: list[FibEntry] = _repeated(0x80)


@dc.dataclass
class StrategyChoice:
    name: NDNName = _name()
    strategy: Optional[Strategy] = _tlv(0x6b)


@dc.dataclass
class StrategyChoiceMsg:
    strategy_choices: list[StrategyChoice] = _repeated(0x80)


@dc.dataclass
class CsInfo:
    capacity: Optional[int] = _tlv(0x83)
    flags: Optional[int] = _tlv(0x6c)
    n_cs_entries: Optional[int] = _tlv(0x87)
    n_hits: Optional[int] = _tlv(0x81)
    n_misses: Optional[int] = _tlv(0x82)


def make_command(module, command, face: Face | None = None, **kwargs):
    ret = make_command_v2(module, command, face, **kwargs)

    # Timestamp and nonce
    ret.append(Component.from_bytes(struct.pack('!Q', timestamp())))
    ret.append(Component.from_bytes(struct.pack('!Q', gen_nonce_64())))

    # SignatureInfo
    signer = DigestSha256Signer()
    sig_info = SignatureInfo()
    write_signature_info(signer, sig_info)
    buf = tlv_encode(sig_info)
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


def make_command_v2(module, command, face: Face | None = None, **kwargs):
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
    cp = ControlParameters(cp=ControlParametersValue())
    for k, v in kwargs.items():
        if k == 'strategy':
            cp.cp.strategy = Strategy(name=v)
        else:
            setattr(cp.cp, k, v)
    ret.append(Component.from_bytes(tlv_encode(cp)))
    return ret


def parse_response(buf):
    buf = parse_and_check_tl(memoryview(buf), 0x65)
    cr = tlv_parse(ControlResponse, buf)
    ret = {}
    ret['status_code'] = cr.status_code
    ret['status_text'] = cr.status_text
    params = cr.body
    for f in dc.fields(ControlParametersValue):
        val = getattr(params, f.name) if params is not None else None
        if isinstance(val, memoryview):
            val = bytes(val)
        ret[f.name] = val
    return ret
