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
    SignatureInfo, get_tl_num_size, TypeNumber, write_tl_num, IncludeBase, parse_and_check_tl
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
    ret = {k.name: getattr(cr, k.name) for k in ControlResponse._encoded_fields}
    return {k: v for k, v in ret.items() if v is not None}
