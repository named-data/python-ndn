import struct
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
        def check_name(need_digest: bool) -> Optional[int]:
            """
            Check the legality of name. Convert name into Name.
            :return: The index of ParametersSha256DigestComponent
            """
            nonlocal name
            digest_pos = None
            if is_binary_str(name):
                # Decode it if it's binary name
                # This makes appending the digest component easier
                name = Name.decode(name)[0]
            elif isinstance(name, str):
                name = Name.from_str(name)
            else:
                # clone to prevent the list being modified
                name = name.copy()
            # From here on, name must be in List[Component, str]
            if not isinstance(name, list):
                raise TypeError('invalid type for name')
            # Check every component
            for i, comp in enumerate(name):
                # If it's string, encode it first
                if isinstance(comp, str):
                    name[i] = Component.from_str(comp)
                    comp = name[i]
                # And then check the type
                if is_binary_str(comp):
                    typ = Component.get_type(comp)
                    if typ == Component.TYPE_INVALID:
                        raise TypeError('invalid type for name component')
                    elif typ == Component.TYPE_PARAMETERS_SHA256:
                        # Params Sha256 can occur at most once
                        if need_digest and digest_pos is None:
                            digest_pos = i
                        else:
                            raise ValueError('unnecessary ParametersSha256DigestComponent in name')
                else:
                    raise TypeError('invalid type for name component')
            return digest_pos

        def get_name_len(need_digest: bool, digest_pos: Optional[int]) -> int:
            """
            Get the length of the name
            :return: the length of the name finally, TL not included
            """
            nonlocal name
            length = reduce(lambda x, y: x + len(y), name, 0)
            if need_digest and digest_pos is None:
                length += 34
            return length

        def get_value_len(name_len: int) -> (int, int, int):
            """
            Get the length of Interest.
            :param name_len: the length of the name, TL not included
            :return: A tuple (Interest length, SignatureInfo length, SignatureValue length).
                TLs are not included.
            """
            sig_info_len = 0
            sig_value_len = 0
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
            return length, sig_info_len, sig_value_len

        def encode_packet() -> (List[memoryview], Optional[memoryview], List[memoryview], Optional[memoryview]):
            """
            Encode the Interest packet. Reserve space for signature and digest.
            :return: A tuple (Signature-covered bytes list,
                              SignatureValue buf,
                              ParametersSha256DigestComponent-covered bytes list,
                              ParametersSha256DigestComponent buf)
            """
            nonlocal wire, name_len, value_len, sig_info_len, sig_value_len, wire_len
            sig_covered_part = []
            sig_value_buf = None
            digest_covered_part = []
            digest_buf = None

            offset = 0
            offset += write_tl_num(Interest.TYPE_INTEREST, wire, offset)
            offset += write_tl_num(value_len, wire, offset)

            # Name
            offset += write_tl_num(Name.TYPE_NAME, wire, offset)
            offset += write_tl_num(name_len, wire, offset)
            cover_start = offset # Signature covers the name
            for i, comp in enumerate(name):
                wire[offset:offset + len(comp)] = comp
                if i == digest_pos:
                    # except the Digest component
                    if offset > cover_start:
                        sig_covered_part.append(wire[cover_start:offset])
                    digest_buf = wire[offset+2:offset+34]
                    cover_start = offset + 34
                offset += len(comp)
            if offset > cover_start:
                sig_covered_part.append(wire[cover_start:offset])
            if need_digest and digest_pos is None:
                # If digest component does not exist, append one
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
                struct.pack_into('!I', wire, offset, interest_param.nonce)
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

            # Signature covers whatever starting from application parameters except SignatureValue
            # Digest covers whatever left
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
        signer = (Signer.get_signer(interest_param.signature_type)
                  if interest_param.signature_type is not None
                  else None)
        if (signer is not None) and (app_param is None):
            app_param = b''
        need_digest = app_param is not None
        digest_pos = check_name(need_digest)

        # calculate length and allocate memory
        name_len = get_name_len(need_digest, digest_pos)
        value_len, sig_info_len, sig_value_len = get_value_len(name_len)
        wire_len = 1 + get_tl_num_size(value_len) + value_len
        ret = bytearray(wire_len)
        wire = memoryview(ret)

        # encode and sign
        sig_covered_part, sig_value_buf, digest_covered_part, digest_buf = encode_packet()
        if signer is not None:
            signer.write_signature_value(sig_value_buf, sig_covered_part, **kwargs)
        if need_digest:
            sha256 = DigestSha256()
            sha256.write_signature_value(digest_buf, digest_covered_part)

        return ret

    @staticmethod
    def parse(wire: BinaryStr):
        # -> name, interest_param, app_param, sig_info, sig_covered_part, sig_value, digest_covered_part, digest
        pass
