from typing import List, Optional, Union
from functools import reduce
from random import randint
from .tlv_var import BinaryStr, VarBinaryStr, write_tl_num, pack_uint_bytes,\
    parse_tl_num, is_binary_str, get_tl_num_size
from .name import Name, Component
from .signer import Signer, DigestSha256


class InterestParam:
    can_be_prefix: bool = False
    must_be_fresh: bool = False
    nonce: Optional[int] = None
    lifetime: int = 4000
    hop_limit: Optional[int] = None
    signature_type: Optional[int] = None


class Interest:
    TYPE_INTEREST = 0x05
    TYPE_CAN_BE_PREFIX = 0x21
    TYPE_MUST_BE_FRESH = 0x12
    TYPE_NONCE = 0x0a
    TYPE_INTEREST_LIFETIME = 0x0c
    TYPE_HOP_LIMIT = 0x22
    TYPE_APPLICATION_PARAMETERS = 0x24
    TYPE_INTEREST_SIGNATURE_INFO = 0x2c
    TYPE_INTEREST_SIGNATURE_VALUE = 0x2e

    @staticmethod
    def make(name: Union[List[Union[BinaryStr, str]], str, BinaryStr],
             interest_param: InterestParam,
             app_param: Optional[BinaryStr] = None,
             **kwargs) -> bytearray:
        """
        Make an encoded Interest packet. kwargs are passed to signer.
        Forwarding Hints are not supported yet.

        :param name: Interest Name. It can be either a string, a encoded Name,
            or a list of Components and/or string.
        :param interest_param: Interest arguments
        :param app_param: Application parameters
        :return: Encoded wire
        """
        def check_name():
            nonlocal name, need_digest, digest_pos
            if is_binary_str(name):
                name = Name.decode(name)
            if isinstance(name, str):
                name = Name.from_str(name)
            if not isinstance(name, list):
                raise TypeError('invalid type for name')
            for i, comp in enumerate(name):
                if isinstance(comp, str):
                    name[i] = Component.from_str(comp)
                    comp = name[i]
                if is_binary_str(comp):
                    typ = Component.get_type(comp)
                    if typ == Component.TYPE_INVALID:
                        raise TypeError('invalid type for name component')
                    elif typ == Component.TYPE_PARAMETERS_SHA256:
                        if need_digest and digest_pos is None:
                            digest_pos = i
                        else:
                            raise ValueError('unnecessary ParametersSha256DigestComponent in name')
                else:
                    raise TypeError('invalid type for name component')

        def get_name_len():
            nonlocal name, need_digest, digest_pos
            length = reduce(lambda x, y: x + len(y), name, 0)
            if need_digest and digest_pos is None:
                length += 34
            return length

        def get_value_len(name_len):
            nonlocal sig_info_len, sig_value_len
            length = 1 + get_tl_num_size(name_len) + name_len
            length += 2 if interest_param.can_be_prefix else 0
            length += 2 if interest_param.must_be_fresh else 0
            length += 6 if interest_param.nonce is not None else 0
            length += 2 + len(pack_uint_bytes(interest_param.lifetime))
            length += 3 if interest_param.hop_limit is not None else 0
            if app_param is not None:
                length += 1 + get_tl_num_size(len(app_param)) + len(app_param)
            if signer is not None:
                sig_info_len = signer.get_signature_info_size(**kwargs) + 3
                length += 1 + get_tl_num_size(sig_info_len) + sig_info_len
                sig_value_len = signer.get_signature_value_size(**kwargs)
                length += 1 + get_tl_num_size(sig_value_len) + sig_value_len
            return length

        def encode_packet():
            nonlocal wire, name_len, value_len, sig_info_len, sig_value_len, wire_len
            digest_covered_part = []
            digest_buf = None
            sig_covered_part = []
            sig_value_buf = None
            cover_start = None

            offset = 0
            offset += write_tl_num(Interest.TYPE_INTEREST, wire, offset)
            offset += write_tl_num(value_len, wire, offset)

            # Name
            offset += write_tl_num(Name.TYPE_NAME, wire, offset)
            offset += write_tl_num(name_len, wire, offset)
            cover_start = offset
            for i, comp in enumerate(name):
                wire[offset:offset + len(comp)] = comp
                if i == digest_pos:
                    if offset > cover_start:
                        sig_covered_part.append(wire[cover_start:offset])
                    digest_buf = wire[offset+2:offset+34]
                    cover_start = offset + 34
                offset += len(comp)
            if offset > cover_start:
                sig_covered_part.append(wire[cover_start:offset])
            if need_digest and digest_pos is None:
                offset += write_tl_num(Component.TYPE_PARAMETERS_SHA256, wire, offset)
                offset += write_tl_num(32, wire, offset)
                digest_buf = wire[offset:offset+32]
                offset += 32

            # Interest arguments
            if interest_param.can_be_prefix:
                offset += write_tl_num(Interest.TYPE_CAN_BE_PREFIX, wire, offset)
                offset += write_tl_num(0, wire, offset)
            if interest_param.must_be_fresh:
                offset += write_tl_num(Interest.TYPE_MUST_BE_FRESH, wire, offset)
                offset += write_tl_num(0, wire, offset)
            if interest_param.nonce is not None:
                offset += write_tl_num(Interest.TYPE_NONCE, wire, offset)
                offset += write_tl_num(4, wire, offset)
                wire[offset:offset+4] = pack_uint_bytes(interest_param.nonce)
                offset += 4
            if interest_param.lifetime is not None:
                offset += write_tl_num(Interest.TYPE_INTEREST_LIFETIME, wire, offset)
                lifetime_buf = pack_uint_bytes(interest_param.lifetime)
                offset += write_tl_num(len(lifetime_buf), wire, offset)
                wire[offset:offset + len(lifetime_buf)] = lifetime_buf
                offset += len(lifetime_buf)
            if interest_param.hop_limit is not None:
                offset += write_tl_num(Interest.TYPE_HOP_LIMIT, wire, offset)
                offset += write_tl_num(1, wire, offset)
                wire[offset] = interest_param.hop_limit
                offset += 1

            cover_start = offset
            if app_param is not None:
                offset += write_tl_num(Interest.TYPE_APPLICATION_PARAMETERS, wire, offset)
                offset += write_tl_num(len(app_param), wire, offset)
                wire[offset:offset+len(app_param)] = app_param
                offset += len(app_param)
            if signer is not None:
                # SignatureInfo
                offset += write_tl_num(Interest.TYPE_INTEREST_SIGNATURE_INFO, wire, offset)
                offset += write_tl_num(sig_info_len, wire, offset)

                offset += write_tl_num(Signer.TYPE_SIGNATURE_TYPE, wire, offset)
                offset += write_tl_num(1, wire, offset)
                wire[offset] = interest_param.signature_type
                offset += 1

                signer.write_signature_info(wire[offset:offset + sig_info_len - 3], **kwargs)
                offset += sig_info_len - 3

                if offset > cover_start:
                    sig_covered_part.append(wire[cover_start:offset])

                # SignatureValue
                offset += write_tl_num(Interest.TYPE_INTEREST_SIGNATURE_VALUE, wire, offset)
                offset += write_tl_num(sig_value_len, wire, offset)
                sig_value_buf = wire[offset:offset + sig_value_len]
                offset += sig_value_len

            digest_covered_part.append(wire[cover_start:offset])
            if offset != wire_len:
                raise RuntimeError('fatal: there is a bug in calculating wire length')
            return sig_covered_part, sig_value_buf, digest_covered_part, digest_buf

        # process input arguments
        name = name.copy()
        signer = (Signer.get_signer(interest_param.signature_type)
                  if interest_param.signature_type is not None
                  else None)
        need_digest = (signer is not None) or (app_param is not None)
        digest_pos = None
        check_name()

        # calculate length and allocate memory
        name_len = get_name_len()
        sig_info_len = 0
        sig_value_len = 0
        value_len = get_value_len(name_len)
        wire_len = 1 + get_tl_num_size(value_len) + value_len
        ret = bytearray(wire_len)
        wire = memoryview(ret)

        # encode
        sig_covered_part, sig_value_buf, digest_covered_part, digest_buf = encode_packet()
        if signer is not None:
            signer.write_signature_value(sig_value_buf, sig_covered_part, **kwargs)
        if need_digest:
            sha256 = DigestSha256()
            sha256.write_signature_value(digest_buf, digest_covered_part)

        return ret

    @staticmethod
    def parse(wire: BinaryStr):
        # -> name, interest_param, app_param, sig_info, sig_covered_part, sig_value, digest_covered_part, digest_buf
        pass
