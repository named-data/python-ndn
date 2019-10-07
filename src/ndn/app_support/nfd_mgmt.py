import struct
from ..utils import timestamp, gen_nonce_64
from ..encoding import Component, Name, ModelField, TlvModel, NameField, UintField, BytesField,\
    SignatureInfo, get_tl_num_size, TypeNumber, write_tl_num
from ..security.sha256_digest_signer import DigestSha256Signer


class ControlParametersValue(TlvModel):
    name = NameField()
    flags = UintField(0x6c)


class ControlParameters(TlvModel):
    cp = ModelField(0x68, ControlParametersValue)


class ControlResponse(TlvModel):
    status_code = UintField(0x66)
    status_text = BytesField(0x67)


def make_reg_route_cmd(name):
    ret = Name.from_str("/localhost/nfd/rib/register")

    # Command parameters
    cp = ControlParameters()
    cp.cp = ControlParametersValue()
    cp.cp.name = name
    cp.cp.flags = 1
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
