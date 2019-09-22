import abc
import struct
from typing import List, Union, Optional, Type
from functools import reduce
from .tlv_var import BinaryStr, VarBinaryStr, write_tl_num, pack_uint_bytes,\
    parse_tl_num, is_binary_str, get_tl_num_size
from .signer import Signer
from .name import Name, Component


class TlvModelMeta(abc.ABCMeta):
    def __new__(mcs, name, bases, attrs, **kwargs):
        cls = super().__new__(mcs, name, bases, attrs)

        # Collect encoded fields
        cls._encoded_fields = []
        for field_name in cls.__dict__:
            if not field_name.startswith('__'):
                field_obj = getattr(cls, field_name)
                if isinstance(field_obj, Field):
                    field_obj.name = field_name
                    cls._encoded_fields.append(field_obj)

        return cls


class Field(metaclass=abc.ABCMeta):
    def __init__(self, type_num: int, default=None):
        self.name = None
        self.type_num = type_num
        self.default = default

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return self.get_value(instance)

    def __set__(self, instance, value):
        instance._field_values[self.name] = value

    def get_value(self, instance):
        if self.name in instance._field_values:
            return instance._field_values[self.name]
        else:
            return self.default

    @abc.abstractmethod
    def encoded_length(self, instance, markers: dict) -> int:
        """
        Preprocess value and get encoded length of this field.
        The function may use markers[f'{self.name}__encoded_length'] to store the length without TL.
        Other marker variables starting with f'{self.name}' may also be used.

        This function may also use other marker variables. However, in that case,
        this field must be unique in a TlvModel. Usage of marker variables should follow
        the name convention defined by specific TlvModel.

        :param instance: instance of TlvModel object
        :param markers: encoding marker variables
        :return: encoded length
        """
        pass

    @abc.abstractmethod
    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        """
        Encode this field into wire. Must be called after encoded_length.

        :param instance: instance of TlvModel object
        :param markers: encoding marker variables
        :param wire: buffer to encode
        :param offset: offset of this field in wire
        :return: encoded_length.
        """
        pass


class UintField(Field):
    def __init__(self, type_num: int, default=None, fixed_len: int = None):
        super().__init__(type_num, default)
        if fixed_len not in {None, 1, 2, 4, 8}:
            raise ValueError("Uint's length should be 1, 2, 4, 8 or None")
        self.fixed_len = fixed_len

    def encoded_length(self, instance, markers: dict) -> int:
        val = self.get_value(instance)
        if val is None:
            return 0
        else:
            if not isinstance(val, int) or val < 0:
                raise TypeError(f'{self.name}=f{val} is not a legal uint')
            tl_size = get_tl_num_size(self.type_num) + 1
            if self.fixed_len is not None:
                ret = self.fixed_len
            else:
                if val <= 0xFF:
                    ret = 1
                elif val <= 0xFFFF:
                    ret = 2
                elif val <= 0xFFFFFFFF:
                    ret = 4
                else:
                    ret = 8
            markers[f'{self.name}__encoded_length'] = ret
            return ret + tl_size

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        val = self.get_value(instance)
        if val is None:
            return 0
        tl_size = get_tl_num_size(self.type_num) + 1
        length = markers[f'{self.name}__encoded_length']
        offset += write_tl_num(self.type_num, wire, offset)
        if length == 1:
            struct.pack_into('!BB', wire, offset, 1, val)
        elif length == 2:
            struct.pack_into('!BH', wire, offset, 2, val)
        elif length == 4:
            struct.pack_into('!BI', wire, offset, 4, val)
        else:
            struct.pack_into('!BQ', wire, offset, 8, val)
        return length + tl_size


class BoolField(Field):
    def encoded_length(self, instance, markers: dict) -> int:
        val = self.get_value(instance)
        tl_size = get_tl_num_size(self.type_num) + 1
        return tl_size if val else 0

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        val = self.get_value(instance)
        if val:
            tl_size = get_tl_num_size(self.type_num) + 1
            offset += write_tl_num(self.type_num, wire, offset)
            wire[offset] = 0
            return tl_size
        else:
            return 0


class SignatureField(Field):
    def __init__(self,
                 info_typ: int,
                 value_typ: int,
                 interest_sig: bool):
        super().__init__(info_typ)
        self.value_typ = value_typ
        self.interest_sig = interest_sig

    def encoded_length(self, instance, markers: dict) -> int:
        if 'signer' not in markers or markers['signer'] is None:
            return 0
        else:
            signer = markers['signer']
            length = 0
            sig_info_len = signer.get_signature_info_size(**markers['signer_args']) + 3
            length += 1 + get_tl_num_size(sig_info_len) + sig_info_len
            sig_value_len = signer.get_signature_value_size(**markers['signer_args'])
            length += 1 + get_tl_num_size(sig_value_len) + sig_value_len
            markers[f'{self.name}__sig_info_len'] = sig_info_len
            markers[f'{self.name}__sig_value_len'] = sig_value_len
            return length

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        if 'signer' not in markers or markers['signer'] is None:
            return 0
        else:
            origin_offset = offset
            signer = markers['signer']
            sig_typ = self.get_value(instance)
            sig_info_len = markers[f'{self.name}__sig_info_len']
            sig_value_len = markers[f'{self.name}__sig_value_len']

            # SignatureInfo
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(sig_info_len, wire, offset)

            # SignatureType
            offset += write_tl_num(Signer.TYPE_SIGNATURE_TYPE, wire, offset)
            offset += write_tl_num(1, wire, offset)
            wire[offset] = sig_typ
            offset += 1

            signer.write_signature_info(wire[offset:offset + sig_info_len - 3], **markers['signer_args'])
            offset += sig_info_len - 3

            if '_sig_cover_start' in markers:
                sig_cover_start = markers['_sig_cover_start']
                markers['sig_cover_part'].append(wire[sig_cover_start:offset])

            # SignatureValue
            offset += write_tl_num(self.value_typ, wire, offset)
            offset += write_tl_num(sig_value_len, wire, offset)
            markers['sig_value_buf'] = wire[offset:offset + sig_value_len]
            offset += sig_value_len
            return offset - origin_offset


class OffsetMarker(Field):
    def __init__(self):
        super().__init__(0)

    def encoded_length(self, instance, markers: dict) -> int:
        return 0

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        markers[self.name] = offset
        return 0


class InterestNameField(Field):
    def encoded_length(self, instance, markers: dict) -> int:
        digest_pos = None
        need_digest = markers['need_digest']
        name = self.get_value(instance)
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
        markers['digest_pos'] = digest_pos
        markers[f'{self.name}__preprocessed_name'] = name

        length = reduce(lambda x, y: x + len(y), name, 0)
        if need_digest and digest_pos is None:
            length += 34
        markers[f'{self.name}__encoded_length'] = length
        return 1 + get_tl_num_size(length) + length

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        origin_offset = offset
        name_len = markers[f'{self.name}__encoded_length']
        name = markers[f'{self.name}__preprocessed_name']
        digest_pos = markers['digest_pos']
        need_digest = markers['need_digest']
        digest_buf = None

        offset += write_tl_num(self.type_num, wire, offset)
        offset += write_tl_num(name_len, wire, offset)
        cover_start = offset  # Signature covers the name
        for i, comp in enumerate(name):
            wire[offset:offset + len(comp)] = comp
            if i == digest_pos:
                # except the Digest component
                if offset > cover_start:
                    markers['sig_cover_part'].append(wire[cover_start:offset])
                digest_buf = wire[offset + 2:offset + 34]
                cover_start = offset + 34
            offset += len(comp)
        if offset > cover_start:
            markers['sig_cover_part'].append(wire[cover_start:offset])
        if need_digest and digest_pos is None:
            # If digest component does not exist, append one
            offset += write_tl_num(Component.TYPE_PARAMETERS_SHA256, wire, offset)
            offset += write_tl_num(32, wire, offset)
            digest_buf = wire[offset:offset + 32]
            offset += 32

        if need_digest:
            markers['digest_buf'] = digest_buf
        return offset - origin_offset


class NameField(Field):
    def encoded_length(self, instance, markers: dict) -> int:
        name = self.get_value(instance)
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

        if isinstance(name, list):
            ret = Name.encoded_length(name)
        else:
            ret = len(name)
        markers[f'{self.name}__preprocessed_name'] = name
        markers[f'{self.name}__encoded_length_with_tl'] = ret
        return ret

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        name = markers[f'{self.name}__preprocessed_name']
        name_len_with_tl = markers[f'{self.name}__encoded_length_with_tl']
        if isinstance(name, list):
            Name.encode(name, wire, offset)
        else:
            wire[offset:offset + name_len_with_tl] = name
        return name_len_with_tl


class BytesField(Field):
    def encoded_length(self, instance, markers: dict) -> int:
        val = self.get_value(instance)
        if val is None:
            return 0
        tl_size = get_tl_num_size(self.type_num) + get_tl_num_size(len(val))
        return tl_size + len(val)

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        val = self.get_value(instance)
        if val is None:
            return 0
        else:
            origin_offset = offset
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(len(val), wire, offset)
            wire[offset:offset+len(val)] = val
            offset += len(val)
            return offset - origin_offset


class TlvModel(metaclass=TlvModelMeta):
    def __init__(self, name: str = ''):
        self._field_values = {}
        self._model_name = name

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        ret = 0
        for field in self._encoded_fields:
            ret += field.encoded_length(self, markers)
        markers[f'{self._model_name}__encoded_length'] = ret
        return ret

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        if f'{self._model_name}__encoded_length' in markers:
            length = markers[f'{self._model_name}__encoded_length']
        else:
            length = self.encoded_length(markers)
        if wire is None:
            wire = bytearray(length)
        wire_view = memoryview(wire)
        for field in self._encoded_fields:
            offset += field.encode_into(self, markers, wire_view, offset)
        return wire

    @staticmethod
    def parse(buf: BinaryStr, markers: Optional[dict] = None):
        pass

    @staticmethod
    def _marker_vars():
        """
        This function is only used for debug and doc.
        :return: a list of marker variables used in this TlvModel.
        """
        return []


class ModelField(Field):
    def __init__(self, type_num: int, model_type: Type[TlvModel]):
        # default should be None here to prevent unintended modification
        super().__init__(type_num, None)
        self.name = None
        self.model_type = model_type

    def encoded_length(self, instance, markers: dict) -> int:
        val = self.get_value(instance)
        if val is None:
            return 0
        if not isinstance(val, self.model_type):
            raise TypeError(f'{self.name}=f{val} is of type {self.model_type}')
        inner_markers = {k: v for k, v in markers.items() if k.startswith('signer')}
        length = val.encoded_length(inner_markers)
        markers[f'{self.name}__inner_markers'] = inner_markers
        markers[f'{self.name}__encoded_length'] = length
        return get_tl_num_size(self.type_num) + get_tl_num_size(length) + length

    def encode_into(self, instance, markers: dict, wire: VarBinaryStr, offset: int = 0) -> int:
        val = self.get_value(instance)
        if val is None:
            return 0
        else:
            inner_markers = markers[f'{self.name}__inner_markers']
            length = markers[f'{self.name}__encoded_length']

            origin_offset = offset
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(length, wire, offset)
            val.encode(wire, offset, inner_markers)
            offset += length
            return offset - origin_offset
