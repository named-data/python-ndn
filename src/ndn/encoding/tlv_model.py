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
import abc
import struct
from enum import Enum, Flag
from typing import Optional, Type, List, Iterable
from functools import reduce
from .tlv_type import BinaryStr, VarBinaryStr, is_binary_str
from .tlv_var import write_tl_num, parse_tl_num, get_tl_num_size
from .name import Name, Component


__all__ = ['DecodeError', 'TlvModel', 'ProcedureArgument', 'OffsetMarker', 'UintField', 'BoolField',
           'NameField', 'BytesField', 'ModelField', 'RepeatedField', 'IncludeBase', 'IncludeBaseError',
           'MapField']


class DecodeError(Exception):
    """
    Raised when there is a critical field (Type is odd) that is unrecognized, redundant or out-of-order.
    """
    pass


class IncludeBaseError(Exception):
    """
    Raised when IncludeBase is used to include a non-base class.
    """
    pass


class IncludeBase:
    """
    Include all fields from a base class.
    """
    def __init__(self, base):
        self.base = base


class TlvModelMeta(abc.ABCMeta):
    """
    Metaclass for TlvModel, used to collect fields.
    """
    def __new__(mcs, name, bases, attrs):
        cls = super().__new__(mcs, name, bases, attrs)

        # Collect encoded fields
        cls._encoded_fields = []
        index_dict = {}
        for field_name in cls.__dict__:
            if not field_name.startswith('__'):
                field_obj = getattr(cls, field_name)
                if isinstance(field_obj, Field):
                    field_obj.name = field_name
                    if field_name not in index_dict:
                        cls._encoded_fields.append(field_obj)
                        index_dict[field_name] = len(cls._encoded_fields) - 1
                    else:
                        cls._encoded_fields[index_dict[field_name]] = field_obj
                elif isinstance(field_obj, IncludeBase):
                    if field_obj.base not in bases:
                        raise IncludeBaseError(f"{field_obj.base} is not one of {name}'s base classes")
                    if not issubclass(field_obj.base, TlvModel):
                        raise IncludeBaseError(f"{field_obj.base} is not a TlvModel")
                    for field in field_obj.base._encoded_fields:
                        if field.name not in index_dict:
                            cls._encoded_fields.append(field)
                            index_dict[field.name] = len(cls._encoded_fields) - 1
                        else:
                            cls._encoded_fields[index_dict[field.name]] = field

        return cls


class Field(metaclass=abc.ABCMeta):
    """
    Field of :class:`TlvModel`.
    A field with value ``None`` will be omitted in encoding TLV.
    There is no required field in a :class:`TlvModel`, i.e. any Field can be ``None``.

    :ivar name: The name of the field
    :vartype name: str

    :ivar type_num: The Type number used in TLV encoding
    :vartype type_num: int

    :ivar default: The default value used for parsing and encoding.

        - If this field is absent during parsing, ``default`` is used to fill in this field.
        - If this field is not explicitly assigned to None before encoding,
          ``default`` is used.
    """
    def __init__(self, type_num: int, default=None):
        """
        Initialize a TLV field.

        :param type_num: Type number.
        :param default: default value used for parsing and encoding.
        """
        self.name = None
        self.type_num = type_num
        self.default = default

    def __get__(self, instance, owner):
        """
        Get the value of this field in a specific instance.
        Simply call :meth:`get_value` if ``instance`` is not ``None``.

        :param instance: the instance that this field is being accessed through.
        :param owner: the owner class of this field.
        :return: the value of this field.
        """
        if instance is None:
            return self
        return self.get_value(instance)

    def __set__(self, instance, value):
        """
        Set the value of this field.

        :param instance: the instance whose field is being set.
        :param value: the new value.
        """
        instance.__dict__[self.name] = value

    def get_value(self, instance):
        """
        Get the value of this field in a specific instance.
        Most fields use ``instance.__dict__`` to access the value.

        :param instance: the instance that this field is being accessed through.
        :return: the value of this field.
        """
        return instance.__dict__.get(self.name, self.default)

    @abc.abstractmethod
    def encoded_length(self, val, markers: dict) -> int:
        r"""
        Preprocess value and get encoded length of this field.
        The function may use ``markers[f'{self.name}##encoded_length']`` to store the length with TL.
        Other marker variables starting with ``f'{self.name}##'`` may also be used.
        Generally, marker variables are only used to store temporary values and avoid duplicated calculation.
        One field should not access to another field's marker by its name.

        This function may also use other marker variables. However, in that case,
        this field must be unique in a TlvModel. Usage of marker variables should follow
        the name convention defined by specific TlvModel.

        :param val: value of this field
        :param markers: encoding marker variables
        :return: encoded length with TL.
            It is expected as the exact length when encoding this field.
            The only exception is ``SignatureValueField`` (invisible to application developer).
        """
        pass

    @abc.abstractmethod
    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        """
        Encode this field into wire. Must be called after :meth:`encoded_length`.

        :param val: value of this field
        :param markers: encoding marker variables
        :param wire: buffer to encode
        :param offset: offset of this field in wire
        :return: encoded length with TL.
            It is expected to be the same as :meth:`encoded_length` returns.
        """
        pass

    @abc.abstractmethod
    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        """
        Parse the value of this field from an encoded wire.

        :param instance: the instance to parse into.
        :param markers: encoding marker variables. Only used in special cases.
        :param wire: the TLV encoded wire.
        :param offset: the offset of this field's Value in ``wire``.
        :param length: the Length of this field's Value.
        :param offset_btl: the offset of this field's TLV.

            .. code-block:: python3

                assert offset == (offset_btl
                                + get_tl_num_size(self.type_num)
                                + get_tl_num_size(length))

        :return: the value.
        """
        pass

    def skipping_process(self, markers: dict, wire: BinaryStr, offset: int):
        """
        Called when this field does not occur in ``wire`` and thus be skipped.

        :param markers: encoding marker variables.
        :param wire: the TLV encoded wire.
        :param offset: the offset where this field should have been if it occurred.
        """
        pass


class ProcedureArgument(Field):
    """
    A marker variable used during encoding or parsing.
    It does not have a value.
    Instead, it provides a way to access a specific variable in ``markers``.
    """
    def __init__(self, default=None):
        super().__init__(-1, default)

    def encoded_length(self, val, markers: dict) -> int:
        return 0

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        return 0

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        pass

    def __get__(self, instance, owner):
        """
        :return: itself.
        """
        return self

    def __set__(self, instance, value):
        """
        This is not allowed and will raise a :class:`TypeError` if called.
        """
        raise TypeError('ProcedureArgument can only be set via set_arg()')

    def get_arg(self, markers: dict):
        """
        Get its value from ``markers``

        :param markers: the markers dict.
        :return: its value.
        """
        return markers.get(f'{self.name}##args', self.default)

    def set_arg(self, markers: dict, val):
        """
        Set its value in ``markers``.

        :param markers: the markers dict.
        :param val: the new value.
        """
        markers[f'{self.name}##args'] = val


class OffsetMarker(ProcedureArgument):
    """
    A marker variable that records its position in TLV wire in terms of offset.
    """
    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        self.set_arg(markers, offset)
        return 0

    def skipping_process(self, markers: dict, wire: BinaryStr, offset: int):
        self.set_arg(markers, offset)


class UintField(Field):
    """
    NonNegativeInteger field.

    Type: :class:`int`

    Its Length is 1, 2, 4 or 8 when present.

    :ivar fixed_len: the fixed value for Length if it's not ``None``.
        Only 1, 2, 4 and 8 are acceptable.
    :vartype fixed_len: int
    :ivar val_base_type: the base type of the value of the field.
        Can be int (default), an Enum or a Flag type.
    """
    def __init__(self, type_num: int, default=None, fixed_len: int = None,
                 val_base_type=int):
        super().__init__(type_num, default)
        if fixed_len not in {None, 1, 2, 4, 8}:
            raise ValueError("Uint's length should be 1, 2, 4, 8 or None")
        if not issubclass(val_base_type, (Flag, Enum, int)):
            raise TypeError("Uint's base class should be int, an Enum, or a Flag")
        self.fixed_len = fixed_len
        self.val_base_type = val_base_type

    def __set__(self, instance, value):
        """
        Set the value of this uint field.
        Will try to convert ``value`` into ``int``.

        :param instance: the instance whose field is being set.
        :param value: the new value.
        """
        if not isinstance(value, int) and value is not None:
            if isinstance(value, (Flag, Enum)):
                value = value.value
            else:
                raise TypeError(f"Cannot convert {value} into a uint field.")
        instance.__dict__[self.name] = value

    def __get__(self, instance, owner):
        """
        Get the value of this uint field in a specific instance.
        Convert the value into the given ``val_base_type``.

        :param instance: the instance that this field is being accessed through.
        :param owner: the owner class of this field.
        :return: the value of this field.
        """
        if instance is None:
            return self
        value = self.get_value(instance)
        if value is not None:
            return self.val_base_type(value)
        else:
            return None

    def encoded_length(self, val, markers: dict) -> int:
        if val is None:
            return 0
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
        if val >= 0x100 ** ret:
            raise ValueError(f'{val} cannot be encoded into {ret} bytes')
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
    """
    Boolean field.

    Type: :class:`bool`

    Its Length is always 0.
    When present, its Value is ``True``.
    When absent, its Value is ``None``, which is equivalent to ``False``.

    .. note::
        The default value is always ``None``.
    """
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
                 signer: ProcedureArgument,
                 covered_part: ProcedureArgument,
                 starting_point: OffsetMarker,
                 value_buffer: ProcedureArgument,
                 shrink_len: ProcedureArgument):
        super().__init__(type_num)
        self.signer = signer
        self.covered_part = covered_part
        self.starting_point = starting_point
        self.value_buffer = value_buffer
        self.shrink_len = shrink_len

    def encoded_length(self, val, markers: dict) -> int:
        signer = self.signer.get_arg(markers)
        if signer is None:
            return 0
        else:
            sig_value_len = signer.get_signature_value_size()
            length = 1 + get_tl_num_size(sig_value_len) + sig_value_len
            markers[f'{self.name}##encoded_length'] = sig_value_len
            return length

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        signer = self.signer.get_arg(markers)
        if signer is None:
            return 0
        else:
            sig_cover_start = self.starting_point.get_arg(markers)
            if sig_cover_start is not None:
                sig_cover_part = self.covered_part.get_arg(markers)
                sig_cover_part.append(wire[sig_cover_start:offset])

            origin_offset = offset
            sig_value_len = markers[f'{self.name}##encoded_length']
            offset += write_tl_num(self.type_num, wire, offset)
            markers[f'{self.name}##wire_length'] = wire[offset:offset+1]
            offset += write_tl_num(sig_value_len, wire, offset)
            self.value_buffer.set_arg(markers, wire[offset:offset + sig_value_len])
            offset += sig_value_len
            return offset - origin_offset

    def calculate_signature(self, markers: dict):
        signer = self.signer.get_arg(markers)
        if signer is not None:
            sig_value_len = markers[f'{self.name}##encoded_length']
            real_len = signer.write_signature_value(self.value_buffer.get_arg(markers),
                                                    self.covered_part.get_arg(markers))
            self.shrink_len.set_arg(markers, sig_value_len - real_len)
            if real_len != sig_value_len:
                if sig_value_len >= 253:
                    raise ValueError(f'Long signatrue with flexible length is not supported: {sig_value_len} >= 253')
                markers[f'{self.name}##wire_length'][0] = real_len

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
        elif isinstance(name, Iterable):
            # clone to prevent the list being modified
            name = list(name)
        # From here on, name must be in List[Component, str]
        if not isinstance(name, list):
            raise TypeError('invalid type for name')
        # Check every component
        for i, comp in enumerate(name):
            # If it's string, encode it first
            if isinstance(comp, str):
                name[i] = Component.from_str(Component.escape_str(comp))
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
            markers[f'{self.name}##preprocessed_name'].append(wire[offset:offset+34])
            # If digest component does not exist, append one
            offset += write_tl_num(Component.TYPE_PARAMETERS_SHA256, wire, offset)
            offset += write_tl_num(32, wire, offset)
            digest_buf = wire[offset:offset + 32]
            offset += 32

        if need_digest:
            self.digest_buffer.set_arg(markers, digest_buf)
        return offset - origin_offset

    def get_final_name(self, markers):
        return markers[f'{self.name}##preprocessed_name']

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
    """
    NDN Name field. Its Type is always :any:`Name.TYPE_NAME`.

    Type: :any:`NonStrictName`
    """
    def __init__(self, default=None, type_number=Name.TYPE_NAME):
        super().__init__(type_number, default)

    def encoded_length(self, val, markers: dict) -> int:
        if val is None:
            return 0
        name = val
        if isinstance(name, str):
            name = Name.from_str(name)
        elif not is_binary_str(name):
            if isinstance(name, Iterable):
                name = list(name)
                for i, comp in enumerate(name):
                    if isinstance(comp, str):
                        name[i] = Component.from_str(Component.escape_str(comp))
                    elif not is_binary_str(comp):
                        raise TypeError('invalid type for name component')
            else:
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
    r"""
    Field for ``*OCTET``.

    Type: :any:`BinaryStr`

    :ivar is_string: If the value is a UTF-8 string. False by default.

    .. note::
        Do not assign it with a :class:`str` if ``is_string`` is False.
    """
    def __init__(self, type_num: int, default=None, is_string: bool = False):
        super().__init__(type_num, default)
        self.is_string = is_string

    def __set__(self, instance, value):
        instance.__dict__[self.name] = value

    def __get__(self, instance, owner):
        if instance is None:
            return self
        value = self.get_value(instance)
        return value

    def encoded_length(self, val, markers: dict) -> int:
        if val is None:
            return 0
        tl_size = get_tl_num_size(self.type_num) + get_tl_num_size(len(val))
        return tl_size + len(val)

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        else:
            if isinstance(val, str):
                val = val.encode('utf-8')
            origin_offset = offset
            offset += write_tl_num(self.type_num, wire, offset)
            offset += write_tl_num(len(val), wire, offset)
            wire[offset:offset+len(val)] = val
            offset += len(val)
            return offset - origin_offset

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        ret = memoryview(wire)[offset:offset+length]
        if self.is_string:
            return bytes(ret).decode('utf-8')
        else:
            return ret


class TlvModel(metaclass=TlvModelMeta):
    r"""
    Used to describe a TLV format.

    :ivar _encoded_fields: a list of :any:`Field` in order.
    :vartype _encoded_fields: List[Field]
    """
    _encoded_fields: List[Field]

    def __repr__(self):
        values = ', '.join(f'{field.name}={field.__get__(self, None).__repr__()}' for field in self._encoded_fields)
        return f'{self.__class__.__name__}({values})'

    def __eq__(self, other):
        """
        Compare two TlvModels

        :param other: the other TlvModel to compare with.
        :return: whether all Fields are equal.
        """
        for field in self._encoded_fields:
            if field.get_value(self) != field.get_value(other):
                return False
        return True

    def asdict(self, dict_factory=dict):
        """
        Return a dict to represent this TlvModel.

        :param dict_factory: class of dict.
        :return: the dict.
        """
        result = []
        for field in self._encoded_fields:
            if isinstance(field, ModelField):
                result.append((field.name, field.__get__(self, None).asdict()))
            elif isinstance(field, RepeatedField):
                result.append((field.name, field.aslist(self)))
            elif isinstance(field, MapField):
                result.append((field.name, field.asdict(self)))
            elif isinstance(field, BytesField):
                val = field.__get__(self, None)
                if isinstance(val, str):
                    result.append((field.name, val))
                else:
                    # memoryview, bytearray, bytes
                    result.append((field.name, bytes(val)))
            else:
                result.append((field.name, field.__get__(self, None)))
        return dict_factory(result)

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        """
        Get the encoded Length of this TlvModel.

        :param markers: encoding marker variables.
        :return: the encoded Length.
        """
        if markers is None:
            markers = {}
        ret = 0
        for field in self._encoded_fields:
            ret += field.encoded_length(field.get_value(self), markers)
        markers['##encoded_length'] = ret
        return ret

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        r"""
        Encode the TlvModel.

        :param wire: the buffer to contain the encoded wire.
            A new :class:`bytearray` will be created if it's ``None``.
        :param offset: the starting offset.
        :param markers: encoding marker variables.
        :return: wire.

        :raises ValueError: some field is assigned with improper value.
        :raises TypeError: some field is assigned with value of wrong type.
        :raises IndexError: wire does not have enough length.
        :raises struct.error: a negative number is assigned to any non-negative integer field.
        """
        if markers is None:
            markers = {}
        if '##encoded_length' in markers:
            length = markers['##encoded_length']
        else:
            length = self.encoded_length(markers)
        if wire is None:
            wire = bytearray(length)
        wire_view = memoryview(wire)
        for field in self._encoded_fields:
            offset += field.encode_into(field.get_value(self), markers, wire_view, offset)
        return wire

    @classmethod
    def parse(cls, wire: BinaryStr, markers: Optional[dict] = None, ignore_critical: bool = False):
        """
        Parse a TlvModel from TLV encoded wire.

        :param wire: the TLV encoded wire.
        :param markers: encoding marker variables.
        :param ignore_critical: whether to ignore unknown critical fields.
        :return: parsed TlvModel.

        :raises DecodeError: a critical field is unrecognized, redundant or out-of-order.
        :raises IndexError: the Length of a field exceeds the size of wire.
        """
        if markers is None:
            markers = {}
        offset = 0
        field_pos = 0
        ret = cls()
        ret.__dict__ = {}  # Clean default values created in __init__
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
                cur_field = ret._encoded_fields[i]
                val = cur_field.parse_from(ret, markers, wire, offset, length, offset_btl)
                cur_field.__set__(ret, val)
                # Set next field
                if isinstance(cur_field, RepeatedField):
                    field_pos = i
                elif isinstance(cur_field, MapField):
                    # Parse the value part for a map
                    field_pos = i
                    offset += length

                    offset_btl = offset
                    typ, size_typ = parse_tl_num(wire, offset)
                    offset += size_typ
                    length, size_len = parse_tl_num(wire, offset)
                    offset += size_len

                    val = cur_field.parse_value(ret, markers, wire, offset, length, offset_btl)
                    cur_field.__set__(ret, val)
                else:
                    field_pos = i + 1
            else:
                # If not found
                if (typ & 1) == 1 and not ignore_critical:
                    raise DecodeError(f'a critical field of type {typ} is unrecognized, redundant or out-of-order')
            offset += length
        return ret


class ModelField(Field):
    r"""
    Field for nested TlvModel.

    Type: :any:`TlvModel`

    :ivar model_type: the type of its value.
    :vartype model_type: :any:`TlvModelMeta`

    :ivar ignore_critical: whether to ignore critical fields (whose Types are odd).
    :vartype ignore_critical: :class:`bool`
    """
    def __init__(self,
                 type_num: int,
                 model_type: Type[TlvModel],
                 copy_in_fields: List[ProcedureArgument] = None,
                 copy_out_fields: List[ProcedureArgument] = None,
                 ignore_critical: bool = False):
        # default should be None here to prevent unintended modification
        super().__init__(type_num, None)
        self.model_type = model_type
        self.copy_in_fields = copy_in_fields if copy_in_fields else {}
        self.copy_out_fields = copy_out_fields if copy_out_fields else {}
        self.ignore_critical = ignore_critical

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
        val = self.model_type.parse(memoryview(wire)[offset:offset+length], inner_markers, self.ignore_critical)
        copy_fields = {f.name for f in self.copy_out_fields}
        for k, v in inner_markers.items():
            if k.split('##')[0] in copy_fields:
                markers[k] = v
        return val


class RepeatedField(Field):
    r"""
    Field for an array of a specific type.
    All elements will be directly encoded into TLV wire in order, sharing the same Type.
    The ``type_num`` of ``element_type`` is used.

    Type: :class:`list`

    :vartype element_type: :any:`Field`
    :ivar element_type: the type of elements in the list.

        .. warning::

            Please always create a new :any:`Field` instance.
            Don't use an existing one.
    """
    def __init__(self, element_type: Field):
        # default should be None here to prevent unintended modification
        super().__init__(element_type.type_num, None)
        self.element_type = element_type

    def get_value(self, instance):
        if self.name not in instance.__dict__:
            instance.__dict__[self.name] = []
        return instance.__dict__[self.name]

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

    def aslist(self, instance):
        ret = []
        for x in self.__get__(instance, None):
            if isinstance(x, TlvModel):
                ret.append(x.asdict())
            elif isinstance(x, memoryview):
                ret.append(bytes(x))
            else:
                ret.append(x)
        return ret


class MapField(Field):
    r"""
    Field for an unordered string or int map of a specific type.
    All elements will be directly encoded into TLV wire in order, sharing the same Type.
    The ``type_num`` of ``element_type`` is used.

    Type: :class:`list`

    :vartype value_type: :any:`Field`
    :ivar value_type: the type of values in the dict.

        .. warning::

            Please always create a new :any:`Field` instance.
            Don't use an existing one.
    """

    def __init__(self, key_type: Field, value_type: Field):
        # default should be None here to prevent unintended modification
        if not isinstance(key_type, BytesField) and not isinstance(key_type, UintField):
            raise TypeError('MapField only supports string and uint to be keys')
        super().__init__(key_type.type_num, None)
        self.key_type = key_type
        self.value_type = value_type

    def get_value(self, instance):
        if self.name not in instance.__dict__:
            instance.__dict__[self.name] = {}
        return instance.__dict__[self.name]

    def encoded_length(self, val, markers: dict) -> int:
        if not val:
            return 0

        ret = 0
        for i, (key, val) in enumerate(val.items()):
            self.key_type.name = f'{self.name}[{i}#k]'
            ret += self.key_type.encoded_length(key, markers)
            self.value_type.name = f'{self.name}[{i}#v]'
            ret += self.value_type.encoded_length(val, markers)

        return ret

    def encode_into(self, val, markers: dict, wire: VarBinaryStr, offset: int) -> int:
        if val is None:
            return 0
        else:
            origin_offset = offset
            for i, (key, val) in enumerate(val.items()):
                self.key_type.name = f'{self.name}[{i}#k]'
                offset += self.key_type.encode_into(key, markers, wire, offset)
                self.value_type.name = f'{self.name}[{i}#v]'
                offset += self.value_type.encode_into(val, markers, wire, offset)
            return offset - origin_offset

    def parse_from(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        # parse_from only parses keys and will not update the value
        dct = self.get_value(instance)
        self.key_type.name = f'{self.name}[{len(dct)}#k]'
        new_key = self.key_type.parse_from(instance, markers, wire, offset, length, offset_btl)
        markers[f'{self.name}#last_key'] = new_key
        return dct

    def parse_value(self, instance, markers: dict, wire: BinaryStr, offset: int, length: int, offset_btl: int):
        # parse_value parses the value associated with the key last parsed.
        dct = self.get_value(instance)
        last_key = markers.get(f'{self.name}#last_key')
        self.value_type.name = f'{self.name}[{len(dct)}#v]'
        val = self.value_type.parse_from(instance, markers, wire, offset, length, offset_btl)
        dct[last_key] = val
        return dct

    def asdict(self, instance):
        ret = {}
        for key, val in self.__get__(instance, None).items():
            if isinstance(val, TlvModel):
                ret[key] = val.asdict()
            elif isinstance(val, memoryview):
                ret[key] = bytes(val)
            else:
                ret[key] = val
        return ret
