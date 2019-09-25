import abc
import struct
from typing import Tuple, Any, Optional, Type, Set, List
from functools import reduce
from .tlv_var import BinaryStr, VarBinaryStr, write_tl_num, pack_uint_bytes,\
    parse_tl_num, is_binary_str, get_tl_num_size
from .name import Name, Component


class DecodeError(Exception):
    pass


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
    def encoded_length(self, val, markers: dict) -> int:
        """
        Preprocess value and get encoded length of this field.
        The function may use markers[f'{self.name}##encoded_length'] to store the length without TL.
        Other marker variables starting with f'{self.name}##' may also be used.

        This function may also use other marker variables. However, in that case,
        this field must be unique in a TlvModel. Usage of marker variables should follow
        the name convention defined by specific TlvModel.

        :param val: value of this field
        :param markers: encoding marker variables
        :return: encoded length
        """
        pass

    @abc.abstractmethod
    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        """
        Encode this field into wire. Must be called after encoded_length.

        :param val: value of this field
        :param markers: encoding marker variables
        :param wire: buffer to encode
        :param offset: offset of this field in wire
        :return: encoded_length.
        """
        pass

    @abc.abstractmethod
    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        pass

    def skipping_process(self, markers: dict, wire: BinaryStr, offset: int):
        pass


class ProcedureArgument(Field):
    def __init__(self):
        super().__init__(-1)

    def encoded_length(self, val, markers: dict) -> int:
        return 0

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        return 0

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        pass

    def __get__(self, instance, owner):
        return self

    def __set__(self, instance, value):
        raise TypeError('ProcedureArgument can only be set via set_arg()')

    def get_arg(self, markers: dict):
        if f'{self.name}##args' not in markers:
            markers[f'{self.name}##args'] = None
        return markers[f'{self.name}##args']

    def set_arg(self, markers: dict, val):
        markers[f'{self.name}##args'] = val


class OffsetMarker(ProcedureArgument):
    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        self.set_arg(markers, offset)
        return 0

    def skipping_process(self, markers: dict, wire: BinaryStr, offset: int):
        self.set_arg(markers, offset)


class UintField(Field):
    def __init__(self, type_num: int, default=None, fixed_len: int = None):
        super().__init__(type_num, default)
        if fixed_len not in {None, 1, 2, 4, 8}:
            raise ValueError("Uint's length should be 1, 2, 4, 8 or None")
        self.fixed_len = fixed_len

    def encoded_length(self, val, markers: dict) -> int:
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
            markers[f'{self.name}##encoded_length'] = ret
            return ret + tl_size

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        tl_size = get_tl_num_size(self.type_num) + 1
        length = markers[f'{self.name}##encoded_length']
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

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        if length == 1:
            return struct.unpack_from('!B', wire, offset)[0]
        elif length == 2:
            return struct.unpack_from('!H', wire, offset)[0]
        elif length == 4:
            return struct.unpack_from('!I', wire, offset)[0]
        elif length == 8:
            return struct.unpack_from('!Q', wire, offset)[0]
        else:
            raise ValueError("Uint's length should be 1, 2, 4 or 8")


class BoolField(Field):
    def encoded_length(self, val, markers: dict) -> int:
        tl_size = get_tl_num_size(self.type_num) + 1
        return tl_size if val else 0

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val:
            tl_size = get_tl_num_size(self.type_num) + 1
            offset += write_tl_num(self.type_num, wire, offset)
            wire[offset] = 0
            return tl_size
        else:
            return 0

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        return True


class SignatureValueField(Field):
    def __init__(self,
                 type_num: int,
                 interest_sig: bool,
                 signer: ProcedureArgument,
                 sign_args: ProcedureArgument,
                 covered_part: ProcedureArgument,
                 starting_point: OffsetMarker,
                 value_buffer: ProcedureArgument):
        super().__init__(type_num)
        self.interest_sig = interest_sig
        self.signer = signer
        self.sign_args = sign_args
        self.covered_part = covered_part
        self.starting_point = starting_point
        self.value_buffer = value_buffer

    def encoded_length(self, val, markers: dict) -> int:
        signer = self.signer.get_arg(markers)
        if signer is None:
            return 0
        else:
            sign_args = self.sign_args.get_arg(markers)
            sig_value_len = signer.get_signature_value_size(**sign_args)
            length = 1 + get_tl_num_size(sig_value_len) + sig_value_len
            markers[f'{self.name}##encoded_length'] = sig_value_len
            return length

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        signer = self.signer.get_arg(markers)
        if signer is None:
            return 0
        else:
            sig_cover_start = self.starting_point.get_arg(markers)
            if sig_cover_start:
                sig_cover_part = self.covered_part.get_arg(markers)
                sig_cover_part.append(wire[sig_cover_start:offset])

            origin_offset = offset
            sig_value_len = markers[f'{self.name}##encoded_length']
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(sig_value_len, wire, offset)
            self.value_buffer.set_arg(markers, wire[offset:offset + sig_value_len])
            offset += sig_value_len
            return offset - origin_offset

    def calculate_signature(self, markers: dict):
        signer = self.signer.get_arg(markers)
        if signer is not None:
            signer.write_signature_value(self.value_buffer.get_arg(markers),
                                         self.covered_part.get_arg(markers),
                                         **self.sign_args.get_arg(markers))

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        sig_buffer = memoryview(wire)[offset:offset+length]
        self.value_buffer.set_arg(markers, sig_buffer)

        sig_cover_start = self.starting_point.get_arg(markers)
        if sig_cover_start is not None:
            sig_cover_part = self.covered_part.get_arg(markers)
            sig_cover_part.append(wire[sig_cover_start:offset_btl])

        return sig_buffer


class InterestNameField(Field):
    def __init__(self,
                 need_digest: ProcedureArgument,
                 signature_covered_part: ProcedureArgument,
                 digest_buffer: ProcedureArgument,
                 default=None):
        super().__init__(Name.TYPE_NAME, default)
        self.need_digest = need_digest
        self.sig_covered_part = signature_covered_part
        self.digest_buffer = digest_buffer

    def encoded_length(self, val, markers: dict) -> int:
        digest_pos = None
        need_digest = self.need_digest.get_arg(markers)
        name = val
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
        markers[f'{self.name}##digest_pos'] = digest_pos
        markers[f'{self.name}##preprocessed_name'] = name

        length = reduce(lambda x, y: x + len(y), name, 0)
        if need_digest and digest_pos is None:
            length += 34
        markers[f'{self.name}##encoded_length'] = length
        return 1 + get_tl_num_size(length) + length

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        origin_offset = offset
        name_len = markers[f'{self.name}##encoded_length']
        name = markers[f'{self.name}##preprocessed_name']
        digest_pos = markers[f'{self.name}##digest_pos']
        need_digest = self.need_digest.get_arg(markers)
        sig_cover_part = self.sig_covered_part.get_arg(markers)
        digest_buf = None

        offset += write_tl_num(self.type_num, wire, offset)
        offset += write_tl_num(name_len, wire, offset)
        cover_start = offset  # Signature covers the name
        for i, comp in enumerate(name):
            wire[offset:offset + len(comp)] = comp
            if i == digest_pos:
                # except the Digest component
                if offset > cover_start:
                    sig_cover_part.append(wire[cover_start:offset])
                digest_buf = wire[offset + 2:offset + 34]
                cover_start = offset + 34
            offset += len(comp)
        if offset > cover_start:
            sig_cover_part.append(wire[cover_start:offset])
        if need_digest and digest_pos is None:
            # If digest component does not exist, append one
            offset += write_tl_num(Component.TYPE_PARAMETERS_SHA256, wire, offset)
            offset += write_tl_num(32, wire, offset)
            digest_buf = wire[offset:offset + 32]
            offset += 32

        if need_digest:
            self.digest_buffer.set_arg(markers, digest_buf)
        return offset - origin_offset

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        name = Name.decode(wire, offset_btl)[0]
        sig_cover_part = self.sig_covered_part.get_arg(markers)
        for ele in name:
            typ = Component.get_type(ele)
            if typ == Component.TYPE_PARAMETERS_SHA256:
                self.digest_buffer.set_arg(markers, Component.get_value(ele))
            else:
                sig_cover_part.append(ele)
        return name


class NameField(Field):
    def __init__(self, default=None):
        super().__init__(Name.TYPE_NAME, default)

    def encoded_length(self, val, markers: dict) -> int:
        if val is None:
            return 0
        name = val
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
        markers[f'{self.name}##preprocessed_name'] = name
        markers[f'{self.name}##encoded_length_with_tl'] = ret
        return ret

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        name = markers[f'{self.name}##preprocessed_name']
        name_len_with_tl = markers[f'{self.name}##encoded_length_with_tl']
        if isinstance(name, list):
            Name.encode(name, wire, offset)
        else:
            wire[offset:offset + name_len_with_tl] = name
        return name_len_with_tl

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        return Name.decode(wire, offset_btl)[0]


class BytesField(Field):
    def encoded_length(self, val, markers: dict) -> int:
        if val is None:
            return 0
        tl_size = get_tl_num_size(self.type_num) + get_tl_num_size(len(val))
        return tl_size + len(val)

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        else:
            origin_offset = offset
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(len(val), wire, offset)
            wire[offset:offset+len(val)] = val
            offset += len(val)
            return offset - origin_offset

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        return memoryview(wire)[offset:offset+length]


class TlvModel(metaclass=TlvModelMeta):
    def __init__(self, name: str = ''):
        self._field_values = {}
        self._model_name = name

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        ret = 0
        for field in self._encoded_fields:
            ret += field.encoded_length(field.get_value(self), markers)
        markers[f'{self._model_name}##encoded_length'] = ret
        return ret

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        if f'{self._model_name}##encoded_length' in markers:
            length = markers[f'{self._model_name}##encoded_length']
        else:
            length = self.encoded_length(markers)
        if wire is None:
            wire = bytearray(length)
        wire_view = memoryview(wire)
        for field in self._encoded_fields:
            offset += field.encode_into(field.get_value(self), markers, wire_view, offset)
        return wire

    @classmethod
    def parse(cls, wire: BinaryStr, markers: Optional[dict] = None):
        if markers is None:
            markers = {}
        offset = 0
        field_pos = 0
        ret = cls()
        while offset < len(wire):
            # Read TL
            offset_btl = offset
            typ, size_typ = parse_tl_num(wire, offset)
            offset += size_typ
            length, size_len = parse_tl_num(wire, offset)
            offset += size_len
            # Search for field
            i = field_pos
            while i < len(ret._encoded_fields):
                if ret._encoded_fields[i].type_num == typ:
                    break
                i += 1
            if i < len(ret._encoded_fields):
                # If found
                # First process skipped fields
                for j in range(field_pos, i):
                    ret._encoded_fields[j].skipping_process(markers, wire, offset_btl)
                # Parse that field
                val = ret._encoded_fields[i].parse_from(ret, markers, wire, offset, length, offset_btl)
                ret._encoded_fields[i].__set__(ret, val)
                # Set next field
                if isinstance(ret._encoded_fields[i], RepeatedField):
                    field_pos = i
                else:
                    field_pos = i + 1
            else:
                # If not found
                if (typ & 1) == 1:
                    raise DecodeError(f'a critical field of type {typ} is unrecognized, redundant or out-of-order')
            offset += length
        return ret


class ModelField(Field):
    def __init__(self,
                 type_num: int,
                 model_type: Type[TlvModel],
                 copy_in_fields: List[ProcedureArgument] = None,
                 copy_out_fields: List[ProcedureArgument] = None):
        # default should be None here to prevent unintended modification
        super().__init__(type_num, None)
        self.model_type = model_type
        self.copy_in_fields = copy_in_fields if copy_in_fields else {}
        self.copy_out_fields = copy_out_fields if copy_out_fields else {}

    def encoded_length(self, val, markers: dict) -> int:
        if val is None:
            return 0
        if not isinstance(val, self.model_type):
            raise TypeError(f'{self.name}=f{val} is of type {self.model_type}')
        copy_fields = {f.name for f in self.copy_in_fields}
        inner_markers = {k: v
                         for k, v in markers.items()
                         if k.split('##')[0] in copy_fields}
        length = val.encoded_length(inner_markers)
        markers[f'{self.name}##inner_markers'] = inner_markers
        markers[f'{self.name}##encoded_length'] = length
        return get_tl_num_size(self.type_num) + get_tl_num_size(length) + length

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        else:
            inner_markers = markers[f'{self.name}##inner_markers']
            length = markers[f'{self.name}##encoded_length']

            origin_offset = offset
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(length, wire, offset)
            val.encode(wire, offset, inner_markers)
            offset += length
            return offset - origin_offset

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        inner_markers = {}
        val = self.model_type.parse(memoryview(wire)[offset:offset+length], inner_markers)
        copy_fields = {f.name for f in self.copy_out_fields}
        for k, v in inner_markers.items():
            if k.split('##')[0] in copy_fields:
                markers[k] = v
        return val


class RepeatedField(Field):
    def __init__(self, element_type: Field):
        # default should be None here to prevent unintended modification
        super().__init__(element_type.type_num, None)
        self.element_type = element_type

    def get_value(self, instance):
        if self.name not in instance._field_values:
            instance._field_values[self.name] = []
        return instance._field_values[self.name]

    def encoded_length(self, val, markers: dict) -> int:
        if not val:
            return 0

        ret = 0
        # Different from ModelField, here changing the name is allowed
        # Because self.element_type is always a new field instance
        # ModelField share a ModelClass with others, and also
        # subfields under a model do not use its name prefix so
        # there may be conflicts
        for i, ele in enumerate(val):
            self.element_type.name = f'{self.name}[{i}]'
            ret += self.element_type.encoded_length(ele, markers)

        return ret  # TL is not included here

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        else:
            origin_offset = offset
            for i, ele in enumerate(val):
                self.element_type.name = f'{self.name}[{i}]'
                offset += self.element_type.encode_into(ele, markers, wire, offset)
            return offset - origin_offset

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        lst = self.get_value(instance)
        self.element_type.name = f'{self.name}[{len(lst)}]'
        new_ele = self.element_type.parse_from(instance, markers, wire, offset, length, offset_btl)
        lst.append(new_ele)
        return lst
