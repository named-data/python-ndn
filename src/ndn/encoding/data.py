from typing import List, Optional, Union
from .tlv_var import BinaryStr, VarBinaryStr, write_tl_num, pack_uint_bytes,\
    parse_tl_num, is_binary_str, get_tl_num_size
from .name import Name, Component
from .signer import Signer, DigestSha256


class DataParam:
    content_type: Optional[int] = 0
    freshness_period: Optional[int] = None
    final_block_id: Optional[BinaryStr] = None
    signature_type: Optional[int] = 0


class Data:
    TYPE_DATA = 0x06
    TYPE_METAINFO = 0x14
    TYPE_CONTENT = 0x15
    TYPE_SIGNATURE_INFO = 0x16
    TYPE_SIGNATURE_VALUE = 0x17
    TYPE_CONTENT_TYPE = 0x18
    TYPE_FRESHNESS_PERIOD = 0x19
    TYPE_FINAL_BLOCK_ID = 0x1a

    @staticmethod
    def make(name: Union[List[Union[BinaryStr, str]], str, BinaryStr],
             param: DataParam,
             content: Optional[BinaryStr] = None,
             **kwargs) -> bytearray:
        def preprocess_name():
            nonlocal name
            if isinstance(name, str):
                name = Name.from_str(name)
            elif isinstance(name, list):
                name = name.copy()
                for i, comp in enumerate(name):
                    if isinstance(comp, str):
                        name[i] = Component.from_str(comp)
                    elif not is_binary_str(comp):
                        raise TypeError('invalid type for name component')
            elif not is_binary_str(name):
                raise TypeError('invalid type for name')

        def get_name_len_with_tl() -> int:
            nonlocal name
            if isinstance(name, list):
                return Name.encoded_length(name)
            else:
                return len(name)

        def get_metainfo_len() -> int:
            ret = 0
            if param.content_type is not None:
                ret += 2 + len(pack_uint_bytes(param.content_type))
            if param.freshness_period is not None:
                ret += 2 + len(pack_uint_bytes(param.freshness_period))
            if param.final_block_id is not None:
                ret += 1 + get_tl_num_size(len(param.final_block_id)) + len(param.final_block_id)
            return ret

        def get_value_len(name_len_with_tl: int, metainfo_len: int) -> (int, int, int):
            nonlocal signer
            sig_info_len = 0
            sig_value_len = 0
            length = name_len_with_tl
            if metainfo_len > 0:
                length += 1 + get_tl_num_size(metainfo_len) + metainfo_len
            if content is not None:
                length += 1 + get_tl_num_size(len(content)) + len(content)
            if signer is not None:
                sig_info_len = signer.get_signature_info_size(**kwargs) + 3
                length += 1 + get_tl_num_size(sig_info_len) + sig_info_len
                sig_value_len = signer.get_signature_value_size(**kwargs)
                length += 1 + get_tl_num_size(sig_value_len) + sig_value_len
            return length, sig_info_len, sig_value_len

        def encode_packet() -> (List[memoryview], Optional[memoryview]):
            nonlocal wire, name_len_with_tl, metainfo_len, value_len, sig_info_len, sig_value_len, wire_len
            sig_covered_part = []
            sig_value_buf = None

            offset = 0
            offset += write_tl_num(Data.TYPE_DATA, wire, offset)
            offset += write_tl_num(value_len, wire, offset)
            cover_start = offset

            # Name
            if isinstance(name, list):
                Name.encode(name, wire, offset)
            else:
                wire[offset:offset+name_len_with_tl] = name
            offset += name_len_with_tl

            # MetaInfo
            if metainfo_len > 0:
                offset += write_tl_num(Data.TYPE_METAINFO, wire, offset)
                offset += write_tl_num(metainfo_len, wire, offset)
                if param.content_type is not None:
                    offset += write_tl_num(Data.TYPE_CONTENT_TYPE, wire, offset)
                    content_type_buf = pack_uint_bytes(param.content_type)
                    offset += write_tl_num(len(content_type_buf), wire, offset)
                    wire[offset:offset + len(content_type_buf)] = content_type_buf
                    offset += len(content_type_buf)
                if param.freshness_period is not None:
                    offset += write_tl_num(Data.TYPE_FRESHNESS_PERIOD, wire, offset)
                    fresh_buf = pack_uint_bytes(param.freshness_period)
                    offset += write_tl_num(len(fresh_buf), wire, offset)
                    wire[offset:offset + len(fresh_buf)] = fresh_buf
                    offset += len(fresh_buf)
                if param.final_block_id is not None:
                    offset += write_tl_num(Data.TYPE_FINAL_BLOCK_ID, wire, offset)
                    offset += write_tl_num(len(param.final_block_id), wire, offset)
                    wire[offset:offset+len(param.final_block_id)] = param.final_block_id
                    offset += len(param.final_block_id)

            # Signature Info
            if signer is not None:
                # SignatureInfo
                offset += write_tl_num(Data.TYPE_SIGNATURE_INFO, wire, offset)
                offset += write_tl_num(sig_info_len, wire, offset)

                offset += write_tl_num(Signer.TYPE_SIGNATURE_TYPE, wire, offset)
                offset += write_tl_num(1, wire, offset)
                wire[offset] = param.signature_type
                offset += 1

                signer.write_signature_info(wire[offset:offset + sig_info_len - 3], **kwargs)
                offset += sig_info_len - 3

                if offset > cover_start:
                    sig_covered_part.append(wire[cover_start:offset])

                # SignatureValue
                offset += write_tl_num(Data.TYPE_SIGNATURE_VALUE, wire, offset)
                offset += write_tl_num(sig_value_len, wire, offset)
                sig_value_buf = wire[offset:offset + sig_value_len]
                offset += sig_value_len

            if offset != wire_len:
                raise RuntimeError('fatal: there is a bug in calculating wire length')
            return sig_covered_part, sig_value_buf

        signer = (Signer.get_signer(param.signature_type)
                  if param.signature_type is not None
                  else None)
        preprocess_name()
        name_len_with_tl = get_name_len_with_tl()
        metainfo_len = get_metainfo_len()
        value_len, sig_info_len, sig_value_len = get_value_len(name_len_with_tl, metainfo_len)
        wire_len = 1 + get_tl_num_size(value_len) + value_len
        ret = bytearray(wire_len)
        wire = memoryview(ret)

        sig_covered_part, sig_value_buf = encode_packet()
        if signer is not None:
            signer.write_signature_value(sig_value_buf, sig_covered_part, **kwargs)

        return ret

    @staticmethod
    def parse(wire: BinaryStr):
        # -> name, param, content, sig_info, sig_covered_part, sig_value
        pass
