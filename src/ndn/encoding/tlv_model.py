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
from collections.abc import Iterable
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
    _encoded_fields: list[Field]

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

    def encoded_length(self, markers: dict | None = None) -> int:
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
               markers: dict | None = None) -> VarBinaryStr:
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
    def parse(cls, wire: BinaryStr, markers: dict | None = None, ignore_critical: bool = False):
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
                 model_type: type[TlvModel],
                 copy_in_fields: list[ProcedureArgument] = None,
                 copy_out_fields: list[ProcedureArgument] = None,
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
"""
Dataclass-based TLV encoding/decoding (v2 API).

Usage::

    from dataclasses import dataclass, field
    from typing import List, Optional
    from ndn.encoding import tlv_encode, tlv_parse, NDNName

    @dataclass
    class Inner:
        value: int = field(default=None, metadata={'tlv_type': 0x01})

    @dataclass
    class Outer:
        name:    NDNName     = field(default=None, metadata={'tlv_type': 0x07})
        count:   int         = field(default=None, metadata={'tlv_type': 0x0a})
        payload: bytes       = field(default=None, metadata={'tlv_type': 0x15})
        sub:     Inner       = field(default=None, metadata={'tlv_type': 0x16})
        tags:    List[bytes] = field(default_factory=list,
                                     metadata={'tlv_type': 0x17})

    wire = tlv_encode(obj)
    obj  = tlv_parse(Outer, wire)

Field-kind inference from Python annotation
-------------------------------------------
+--------------------------------------------+----------+------------------+
| Annotation                                 | Kind     | Old equivalent   |
+============================================+==========+==================+
| int / Enum / Flag subclass                 | uint     | UintField        |
+--------------------------------------------+----------+------------------+
| bool                                       | bool     | BoolField        |
+--------------------------------------------+----------+------------------+
| bytes / bytearray / memoryview             | bytes    | BytesField       |
+--------------------------------------------+----------+------------------+
| str                                        | str      | BytesField       |
|                                            |          | (is_string=True) |
+--------------------------------------------+----------+------------------+
| NDNName (sentinel)                         | name     | NameField        |
+--------------------------------------------+----------+------------------+
| Any @dataclass type                        | model    | ModelField       |
+--------------------------------------------+----------+------------------+
| List[T]                                    | repeated | RepeatedField    |
+--------------------------------------------+----------+------------------+
| Dict[K, V]                                 | map      | MapField         |
+--------------------------------------------+----------+------------------+
| None  + field_type='offset_marker'         | (zero)   | OffsetMarker     |
+--------------------------------------------+----------+------------------+
| bytes + field_type='sig_value'             | (special)| SignatureValue   |
+--------------------------------------------+----------+------------------+
| NDNName + field_type='interest_name'       | (special)| InterestNameField|
+--------------------------------------------+----------+------------------+

Supported metadata keys
-----------------------
``'tlv_type'``       int   TLV type number (required except for offset_marker)
``'fixed_len'``      int   Force uint value width: 1, 2, 4, or 8 bytes
``'ignore_critical'  bool  Suppress DecodeError for nested model parsing
``'field_type'``     str   Explicit kind override when inference is insufficient

For **map** fields (``Dict[K, V]``):
``'val_tlv_type'``     int  TLV type for map values (required)

For **sig_value** fields:
``'cover_start'``      str  Name of the offset_marker field where sig coverage begins
``'digest_cover_start' str  Same or different offset_marker; where digest coverage begins
``'digest_cover_end'`` str  Offset_marker after sig_value; where digest coverage ends

Signature machinery markers (set by caller before tlv_encode / tlv_parse):
``markers['##signer']``        Signer instance; absent means unsigned
``markers['##need_digest']``   True ⟹ insert/compute ParametersSha256DigestComponent

Signature machinery markers (set by tlv_encode / tlv_parse internally):
``markers['##sig_covered_part']``   list[memoryview | bytes]: regions covered by sig
``markers['##sig_value_buf']``      writable memoryview into the placeholder bytes
``markers['##shrink_len']``         int: bytes trimmed from end after sig finalization
``markers['##digest_buf']``         writable memoryview into the digest component value
``markers[fname]``                  int: recorded byte offset for each offset_marker field
"""
import dataclasses
import struct
import typing
import weakref
from enum import Enum, Flag
from hashlib import sha256
from types import UnionType

from .tlv_type import VarBinaryStr, is_binary_str
from .tlv_var import write_tl_num, parse_tl_num, get_tl_num_size
from .name import Name, Component


__all__ += [
    'tlv_encode', 'tlv_parse', 'NDNName', 'DecodeError',
    'tlv_get_arg', 'tlv_set_arg',
]

# Kinds that occupy zero wire bytes and may not have a 'tlv_type' metadata key.
_ZERO_WIRE_KINDS = frozenset({'offset_marker'})


# ---------------------------------------------------------------------------
# NDNName sentinel — used as a type annotation for NDN Name fields
# ---------------------------------------------------------------------------

class NDNName:
    """
    Sentinel annotation type that marks a field as an NDN Name.

    Use it wherever you would have used :class:`~ndn.encoding.NameField` in
    the old metaclass API::

        name: NDNName = field(default=None, metadata={'tlv_type': 0x07})
        # repeated Names:
        names: List[NDNName] = field(default_factory=list,
                                     metadata={'tlv_type': 0x07})

    The actual runtime value is :any:`FormalName` (a list of encoded
    component bytes), exactly as returned by the old NameField.
    """


# ---------------------------------------------------------------------------
# Annotation helpers
# ---------------------------------------------------------------------------

def _unwrap_optional(annotation):
    """Return T for Optional[T] = Union[T, None]; otherwise return unchanged."""
    if typing.get_origin(annotation) in (typing.Union, UnionType):
        args = [a for a in typing.get_args(annotation) if a is not type(None)]
        if len(args) == 1:
            return args[0]
    return annotation


def _infer_kind(annotation, metadata: dict) -> str:
    """
    Determine the TLV field kind from a Python type annotation plus metadata.

    Returns one of: ``'uint'``, ``'bool'``, ``'bytes'``, ``'str'``,
    ``'name'``, ``'model'``, ``'repeated'``.

    The ``'field_type'`` metadata key overrides automatic inference.
    """
    if 'field_type' in metadata:
        return metadata['field_type']

    annotation = _unwrap_optional(annotation)
    origin = typing.get_origin(annotation)

    if origin is list:
        return 'repeated'
    if origin is dict:
        return 'map'
    if annotation is NDNName:
        return 'name'
    # bool must be checked before int since bool is a subclass of int
    if annotation is bool:
        return 'bool'
    if annotation is int or (
            isinstance(annotation, type)
            and issubclass(annotation, (int, Enum, Flag))
            and annotation is not bool):
        return 'uint'
    if annotation in (bytes, bytearray, memoryview):
        return 'bytes'
    if annotation is str:
        return 'str'
    if dataclasses.is_dataclass(annotation):
        return 'model'

    raise TypeError(
        f'Cannot infer TLV field kind from annotation {annotation!r}. '
        f"Use metadata key 'field_type' to override."
    )


def _element_annotation(annotation):
    """Extract T from List[T]; falls back to bytes."""
    annotation = _unwrap_optional(annotation)
    args = typing.get_args(annotation)
    return args[0] if args else bytes


def _map_annotations(annotation):
    """Extract (K, V) from Dict[K, V]; falls back to (str, bytes)."""
    annotation = _unwrap_optional(annotation)
    args = typing.get_args(annotation)
    if len(args) == 2:
        return args[0], args[1]
    return str, bytes


def _map_key_meta(metadata: dict) -> dict:
    """Build a synthetic metadata dict for a map key sub-field."""
    return {'tlv_type': metadata['tlv_type']}


def _map_val_meta(metadata: dict) -> dict:
    """Build a synthetic metadata dict for a map value sub-field."""
    m = {'tlv_type': metadata['val_tlv_type']}
    if 'ignore_critical' in metadata:
        m['ignore_critical'] = metadata['ignore_critical']
    return m


# ---------------------------------------------------------------------------
# Per-class schema cache
# ---------------------------------------------------------------------------

@dataclasses.dataclass(frozen=True, slots=True)
class _FieldSpec:
    """Everything the encoder/parser needs about one field, resolved once."""
    name: str
    kind: str
    metadata: typing.Mapping
    annotation: typing.Any
    tlv_type: typing.Optional[int]
    enum_cls: typing.Optional[type] = None
    elem: typing.Optional['_FieldSpec'] = None
    key: typing.Optional['_FieldSpec'] = None
    val: typing.Optional['_FieldSpec'] = None


def _make_spec(name: str, annotation, metadata) -> _FieldSpec:
    kind = _infer_kind(annotation, metadata)
    annotation = _unwrap_optional(annotation)
    enum_cls = elem = key = val = None
    if kind == 'uint' and isinstance(annotation, type) and issubclass(annotation, (Enum, Flag)):
        enum_cls = annotation
    elif kind == 'repeated':
        elem = _make_spec(name, _element_annotation(annotation), metadata)
    elif kind == 'map':
        key_ann, val_ann = _map_annotations(annotation)
        key = _make_spec(name, key_ann, _map_key_meta(metadata))
        val = _make_spec(name, val_ann, _map_val_meta(metadata))
    return _FieldSpec(name, kind, metadata, annotation, metadata.get('tlv_type'),
                      enum_cls, elem, key, val)


_SCHEMA_CACHE: 'weakref.WeakKeyDictionary[type, tuple[_FieldSpec, ...]]' = weakref.WeakKeyDictionary()


def _get_schema(cls) -> tuple[_FieldSpec, ...]:
    """
    Return the TLV field specs of dataclass *cls* in declaration order.

    Built on first use rather than at class definition so that forward
    references to classes defined later in the same module can be resolved.
    Fields with neither ``tlv_type`` nor ``field_type`` metadata are skipped.
    """
    try:
        return _SCHEMA_CACHE[cls]
    except KeyError:
        pass
    hints = typing.get_type_hints(cls)
    specs = []
    for f in dataclasses.fields(cls):
        if 'tlv_type' not in f.metadata and 'field_type' not in f.metadata:
            continue
        spec = _make_spec(f.name, hints[f.name], f.metadata)
        if spec.kind not in _ZERO_WIRE_KINDS and spec.tlv_type is None:
            continue
        specs.append(spec)
    schema = tuple(specs)
    _SCHEMA_CACHE[cls] = schema
    return schema


# ---------------------------------------------------------------------------
# Interest-name helpers (used by both pass-1 and pass-2)
# ---------------------------------------------------------------------------

def _encoded_length_interest_name(fname: str, val, metadata: dict,
                                   markers: dict) -> int:
    """
    Size pass for an Interest Name field.

    Mirrors ``InterestNameField.encoded_length``.  If ``markers['##need_digest']``
    is truthy and the name does not already contain a
    ``ParametersSha256DigestComponent``, 34 extra bytes are reserved for one.
    """
    if val is None:
        return 0
    type_num = metadata['tlv_type']
    need_digest = markers.get('##need_digest', False)

    # Normalize to a list of component bytes.
    if isinstance(val, str):
        name = Name.from_str(val)
    elif is_binary_str(val):
        name = Name.decode(val)[0]
    else:
        name = list(val)
    for i, comp in enumerate(name):
        if isinstance(comp, str):
            name[i] = Component.from_str(Component.escape_str(comp))
        elif not is_binary_str(comp):
            raise TypeError(f'{fname}: invalid name component {comp!r}')

    # Locate an existing ParametersSha256DigestComponent (at most one allowed).
    digest_pos = None
    for i, comp in enumerate(name):
        if Component.get_type(comp) == Component.TYPE_PARAMETERS_SHA256:
            if len(Component.get_value(comp)) != 32:
                raise ValueError(
                    f'{fname}: ParametersSha256DigestComponent must be 32 bytes')
            if need_digest:
                if digest_pos is None:
                    digest_pos = i
                else:
                    raise ValueError(
                        f'{fname}: multiple ParametersSha256DigestComponent in name')

    markers[f'{fname}##digest_pos'] = digest_pos
    markers[f'{fname}##preprocessed_name'] = name

    comp_total = sum(len(c) for c in name)
    if need_digest and digest_pos is None:
        # Reserve space for a new digest component: T(1B) + L(1B) + V(32B).
        comp_total += (get_tl_num_size(Component.TYPE_PARAMETERS_SHA256)
                       + get_tl_num_size(32) + 32)

    markers[f'{fname}##name_value_len'] = comp_total
    return get_tl_num_size(type_num) + get_tl_num_size(comp_total) + comp_total


def _encode_into_interest_name(fname: str, val, metadata: dict, markers: dict,
                                wire: VarBinaryStr, offset: int) -> int:
    """
    Write pass for an Interest Name field.

    Mirrors ``InterestNameField.encode_into``.  Appends non-digest name
    components to ``markers['##sig_covered_part']`` (wire slices) and stores
    the writable digest-value buffer in ``markers['##digest_buf']``.
    """
    if val is None:
        return 0
    type_num = metadata['tlv_type']
    name = markers[f'{fname}##preprocessed_name']
    comp_total = markers[f'{fname}##name_value_len']
    digest_pos = markers[f'{fname}##digest_pos']
    need_digest = markers.get('##need_digest', False)
    sig_covered_part = markers.setdefault('##sig_covered_part', [])

    origin = offset
    t_sz = write_tl_num(type_num, wire, offset);  offset += t_sz
    l_sz = write_tl_num(comp_total, wire, offset); offset += l_sz
    cover_start = offset

    for i, comp in enumerate(name):
        comp_len = len(comp)
        wire[offset:offset + comp_len] = comp
        if i == digest_pos:
            if offset > cover_start:
                sig_covered_part.append(wire[cover_start:offset])
            # Value of the digest component sits after T + L (each 1 byte for
            # TYPE_PARAMETERS_SHA256=2 < 253 and length=32 < 253).
            c_t_sz = get_tl_num_size(Component.TYPE_PARAMETERS_SHA256)
            c_l_sz = get_tl_num_size(32)
            markers['##digest_buf'] = wire[offset + c_t_sz + c_l_sz:offset + comp_len]
            cover_start = offset + comp_len
        offset += comp_len

    if offset > cover_start:
        sig_covered_part.append(wire[cover_start:offset])

    if need_digest and digest_pos is None:
        # Append a new ParametersSha256DigestComponent at the end of the name.
        c_t_sz = write_tl_num(Component.TYPE_PARAMETERS_SHA256, wire, offset)
        offset += c_t_sz
        c_l_sz = write_tl_num(32, wire, offset)
        offset += c_l_sz
        markers['##digest_buf'] = wire[offset:offset + 32]
        # Keep the preprocessed name up-to-date for get_final_name use.
        name.append(bytes(wire[offset - c_t_sz - c_l_sz:offset + 32]))
        offset += 32

    return offset - origin


# ---------------------------------------------------------------------------
# Post-encoding finalization (signature + SHA-256 digest)
# ---------------------------------------------------------------------------

def _finalize_encode(markers: dict, mv: memoryview, model_end: int) -> int:
    """
    Called by :func:`tlv_encode` after all bytes have been written.

    1. Asks the signer to fill in the signature-value placeholder, updates the
       inline length byte if the actual signature is shorter (ECDSA), and
       records ``markers['##shrink_len']``.
    2. If ``markers['##need_digest']`` is set, computes ``SHA-256`` over the
       digest-covered range and writes it into the name's digest-component
       placeholder (``markers['##digest_buf']``).

    Returns *shrink_size* (0 for fixed-length signature schemes like HMAC/EdDSA).
    All offsets in *markers* are absolute positions within *mv*.
    """
    signer = markers.get('##signer')
    shrink_size = 0

    if signer is not None and '##sig_value_buf' in markers:
        sig_value_buf = markers['##sig_value_buf']
        alloc_size = len(sig_value_buf)
        real_size = signer.write_signature_value(
            sig_value_buf, markers.get('##sig_covered_part', []))
        shrink_size = alloc_size - real_size
        markers['##shrink_len'] = shrink_size
        if shrink_size > 0:
            if alloc_size >= 253:
                raise ValueError(
                    f'Signature with variable length ≥ 253 bytes is not supported '
                    f'(allocated {alloc_size})')
            markers['##sig_wire_l_field'][0] = real_size

    if markers.get('##need_digest') and '##digest_buf' in markers:
        d_start_field = markers.get('##_digest_cover_start_field')
        d_end_field   = markers.get('##_digest_cover_end_field')
        d_start = markers[d_start_field] if (d_start_field and d_start_field in markers) else 0
        d_end   = markers[d_end_field]   if (d_end_field   and d_end_field   in markers) else model_end
        d_end  -= shrink_size
        markers['##digest_buf'][:] = sha256(bytes(mv[d_start:d_end])).digest()

    return shrink_size


# ---------------------------------------------------------------------------
# Encoding — pass 1: size computation
# ---------------------------------------------------------------------------

def _uint_value_len(val: int, fname: str, fixed_len) -> int:
    if fixed_len is not None:
        if fixed_len not in (1, 2, 4, 8):
            raise ValueError("uint fixed_len must be 1, 2, 4, or 8")
        n = fixed_len
    elif val <= 0xFF:
        n = 1
    elif val <= 0xFFFF:
        n = 2
    elif val <= 0xFFFFFFFF:
        n = 4
    else:
        n = 8
    if val >= 0x100 ** n:
        raise ValueError(f'{fname}={val!r} cannot be encoded into {n} bytes')
    return n


def _encoded_length_field(fname: str, val, spec: _FieldSpec, markers: dict) -> int:
    """
    Compute the encoded byte count of one TLV field (T + L + V).

    Intermediate values are cached in *markers* under ``fname##...`` keys,
    exactly mirroring the convention used by the v1 :class:`~ndn.encoding.Field`
    subclasses.  Returns 0 when the field is absent (*val* is ``None``/falsy
    for bool).
    """
    kind = spec.kind
    # Zero-wire kinds: handled before looking up tlv_type.
    if kind == 'offset_marker':
        return 0

    if kind == 'sig_value':
        signer = markers.get('##signer')
        if signer is None:
            return 0
        type_num = spec.tlv_type
        sig_size = signer.get_signature_value_size()
        markers[f'{fname}##sig_size'] = sig_size
        markers.setdefault('##sig_covered_part', [])
        return get_tl_num_size(type_num) + get_tl_num_size(sig_size) + sig_size

    if kind == 'interest_name':
        return _encoded_length_interest_name(fname, val, spec.metadata, markers)

    type_num = spec.tlv_type

    # BoolField: present if truthy, absent otherwise
    if kind == 'bool':
        return (get_tl_num_size(type_num) + 1) if val else 0

    if val is None:
        return 0

    if kind == 'uint':
        if isinstance(val, (Enum, Flag)):
            val = val.value
        if not isinstance(val, int) or val < 0:
            raise TypeError(f'{fname}={val!r} is not a non-negative integer')
        fixed_len = spec.metadata.get('fixed_len')
        vlen = _uint_value_len(val, fname, fixed_len)
        markers[f'{fname}##encoded_length'] = vlen
        # L for uint is always 1 byte because vlen ∈ {1,2,4,8} < 253
        return get_tl_num_size(type_num) + 1 + vlen

    if kind in ('bytes', 'str'):
        if isinstance(val, str):
            raw = val.encode('utf-8')
            markers[f'{fname}##encoded_str'] = raw
        else:
            raw = val
        n = len(raw)
        return get_tl_num_size(type_num) + get_tl_num_size(n) + n

    if kind == 'name':
        # Normalise to list-of-components or a pre-encoded binary blob
        name_val = val
        if isinstance(name_val, str):
            name_val = Name.from_str(name_val)
        elif not is_binary_str(name_val):
            if hasattr(name_val, '__iter__'):
                name_val = list(name_val)
                for i, comp in enumerate(name_val):
                    if isinstance(comp, str):
                        name_val[i] = Component.from_str(Component.escape_str(comp))
                    elif not is_binary_str(comp):
                        raise TypeError(f'{fname}: invalid name component type')
            else:
                raise TypeError(f'{fname}: invalid name type')
        if isinstance(name_val, list):
            total_with_tl = Name.encoded_length(name_val)
        else:
            total_with_tl = len(name_val)
        markers[f'{fname}##preprocessed_name'] = name_val
        markers[f'{fname}##encoded_length_with_tl'] = total_with_tl
        return total_with_tl

    if kind == 'model':
        if not isinstance(val, spec.annotation):
            raise TypeError(f'{fname}={val!r} is not of type {spec.annotation!r}')
        inner_markers: dict = {}
        length = _encoded_length_model(val, inner_markers)
        markers[f'{fname}##inner_markers'] = inner_markers
        markers[f'{fname}##encoded_length'] = length
        return get_tl_num_size(type_num) + get_tl_num_size(length) + length

    if kind == 'repeated':
        if not val:
            return 0
        elem = spec.elem
        total = 0
        for i, ele in enumerate(val):
            total += _encoded_length_field(f'{fname}[{i}]', ele, elem, markers)
        return total

    if kind == 'map':
        if not val:
            return 0
        key_spec, val_spec = spec.key, spec.val
        total = 0
        for i, (k, v) in enumerate(val.items()):
            total += _encoded_length_field(f'{fname}[{i}#k]', k, key_spec, markers)
            total += _encoded_length_field(f'{fname}[{i}#v]', v, val_spec, markers)
        return total

    raise TypeError(f'Unknown field kind {kind!r} for {fname!r}')


def _encoded_length_model(obj, markers: dict) -> int:
    """Compute the total encoded length for all TLV fields of a dataclass object."""
    total = 0
    for spec in _get_schema(type(obj)):
        total += _encoded_length_field(spec.name, getattr(obj, spec.name), spec, markers)
    markers['##encoded_length'] = total
    return total


# ---------------------------------------------------------------------------
# Encoding — pass 2: write bytes
# ---------------------------------------------------------------------------

def _encode_into_field(fname: str, val, spec: _FieldSpec,
                       markers: dict, wire: VarBinaryStr, offset: int) -> int:
    """
    Write one TLV field into *wire* at *offset*.

    *wire* must be a writable :class:`memoryview` (or :class:`bytearray`).
    Returns the number of bytes written.  Must be called after the matching
    :func:`_encoded_length_field` call so that ``markers`` is populated.
    """
    kind = spec.kind
    metadata = spec.metadata
    # Zero-wire kinds: handled before looking up tlv_type.
    if kind == 'offset_marker':
        markers[fname] = offset
        return 0

    if kind == 'sig_value':
        signer = markers.get('##signer')
        if signer is None:
            return 0
        type_num = spec.tlv_type
        sig_size = markers[f'{fname}##sig_size']
        # Collect the covered region: from cover_start up to current offset.
        cover_start_field = metadata.get('cover_start')
        cover_start = markers.get(cover_start_field, 0) if cover_start_field else 0
        markers.setdefault('##sig_covered_part', []).append(wire[cover_start:offset])
        # Store digest-coverage field names for _finalize_encode.
        for mkey in ('digest_cover_start', 'digest_cover_end'):
            if mkey in metadata:
                markers[f'##_{mkey}_field'] = metadata[mkey]
        # Write T + L (stored for in-place shrink) + placeholder V.
        t_sz = write_tl_num(type_num, wire, offset)
        l_off = offset + t_sz
        l_sz = write_tl_num(sig_size, wire, l_off)
        markers['##sig_wire_l_field'] = wire[l_off:l_off + l_sz]
        v_start = l_off + l_sz
        markers['##sig_value_buf'] = wire[v_start:v_start + sig_size]
        return t_sz + l_sz + sig_size

    if kind == 'interest_name':
        return _encode_into_interest_name(fname, val, metadata, markers, wire, offset)

    type_num = spec.tlv_type

    if kind == 'bool':
        if val:
            t_size = write_tl_num(type_num, wire, offset)
            wire[offset + t_size] = 0           # L = 0
            return t_size + 1
        return 0

    if val is None:
        return 0

    if kind == 'uint':
        if isinstance(val, (Enum, Flag)):
            val = val.value
        vlen = markers[f'{fname}##encoded_length']
        t_size = write_tl_num(type_num, wire, offset)
        if vlen == 1:
            struct.pack_into('!BB', wire, offset + t_size, 1, val)
        elif vlen == 2:
            struct.pack_into('!BH', wire, offset + t_size, 2, val)
        elif vlen == 4:
            struct.pack_into('!BI', wire, offset + t_size, 4, val)
        else:
            struct.pack_into('!BQ', wire, offset + t_size, 8, val)
        return t_size + 1 + vlen               # T + L(1 byte) + V

    if kind in ('bytes', 'str'):
        raw = markers.get(f'{fname}##encoded_str')
        if raw is None:
            raw = val.encode('utf-8') if isinstance(val, str) else val
        n = len(raw)
        t_size = write_tl_num(type_num, wire, offset)
        l_size = write_tl_num(n, wire, offset + t_size)
        v_start = offset + t_size + l_size
        wire[v_start:v_start + n] = raw        # zero-copy slice assignment
        return t_size + l_size + n

    if kind == 'name':
        name_val = markers[f'{fname}##preprocessed_name']
        name_len = markers[f'{fname}##encoded_length_with_tl']
        if isinstance(name_val, list):
            Name.encode(name_val, wire, offset)
        else:
            wire[offset:offset + name_len] = name_val
        return name_len

    if kind == 'model':
        inner_markers = markers[f'{fname}##inner_markers']
        length = markers[f'{fname}##encoded_length']
        t_size = write_tl_num(type_num, wire, offset)
        l_size = write_tl_num(length, wire, offset + t_size)
        _encode_into_model(val, inner_markers, wire, offset + t_size + l_size)
        return t_size + l_size + length

    if kind == 'repeated':
        if not val:
            return 0
        elem = spec.elem
        total = 0
        for i, ele in enumerate(val):
            total += _encode_into_field(
                f'{fname}[{i}]', ele, elem, markers, wire, offset + total)
        return total

    if kind == 'map':
        if not val:
            return 0
        key_spec, val_spec = spec.key, spec.val
        total = 0
        for i, (k, v) in enumerate(val.items()):
            total += _encode_into_field(
                f'{fname}[{i}#k]', k, key_spec, markers, wire, offset + total)
            total += _encode_into_field(
                f'{fname}[{i}#v]', v, val_spec, markers, wire, offset + total)
        return total

    raise TypeError(f'Unknown field kind {kind!r} for {fname!r}')


def _encode_into_model(obj, markers: dict, wire: VarBinaryStr, offset: int) -> None:
    """Write all TLV fields of a dataclass object into *wire* starting at *offset*."""
    for spec in _get_schema(type(obj)):
        offset += _encode_into_field(
            spec.name, getattr(obj, spec.name), spec, markers, wire, offset)


# ---------------------------------------------------------------------------
# Public encode entry point
# ---------------------------------------------------------------------------

def tlv_encode(obj, wire=None, offset: int = 0, markers: dict = None):
    """
    Encode a dataclass TLV object.

    **Allocating form** — ``tlv_encode(obj)``
        Allocates a new :class:`bytearray`, fills it, and returns it.

    **In-place form** — ``tlv_encode(obj, wire, offset=0)``
        Encodes into an existing *wire* (:class:`bytearray` or writable
        :class:`memoryview`) starting at *offset*.  Returns a zero-copy
        :class:`memoryview` slice of the written region.

    :param obj: dataclass instance to encode.
    :param wire: optional writable buffer.
    :param offset: starting byte offset within *wire*.
    :param markers: optional shared markers dict (for multi-model coordination).
    :return: :class:`bytearray` (allocating) or :class:`memoryview` (in-place).
    """
    if markers is None:
        markers = {}
    total = _encoded_length_model(obj, markers)
    if wire is None:
        buf = bytearray(total)
        mv = memoryview(buf)
        _encode_into_model(obj, markers, mv, 0)
        shrink = _finalize_encode(markers, mv, total)
        if shrink:
            # Can't resize bytearray while memoryview exports are live (the sig/digest
            # slices in markers still reference mv).  Return a trimmed copy instead.
            return bytearray(mv[:total - shrink])
        return buf
    mv = memoryview(wire)
    _encode_into_model(obj, markers, mv, offset)
    shrink = _finalize_encode(markers, mv, offset + total)
    return mv[offset:offset + total - shrink]


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _make_default_instance(cls):
    """
    Create a dataclass instance with all fields set to their defaults.

    Uses ``object.__new__`` to bypass ``__init__``, then sets each field:
    - ``field(default=X)``          → X
    - ``field(default_factory=F)``  → F()
    - no default                    → None  (same behaviour as old TlvModel.parse)
    """
    obj = object.__new__(cls)
    for f in dataclasses.fields(cls):
        if f.default is not dataclasses.MISSING:
            object.__setattr__(obj, f.name, f.default)
        elif f.default_factory is not dataclasses.MISSING:
            object.__setattr__(obj, f.name, f.default_factory())
        else:
            object.__setattr__(obj, f.name, None)
    return obj


def _parse_value(fname: str, spec: _FieldSpec,
                 wire, offset: int, length: int, offset_btl: int,
                 ignore_critical: bool):
    """
    Parse a single TLV *value* (V only, not T or L) from *wire*.

    :param fname: field name (for error messages).
    :param spec: resolved field spec.
    :param wire: memoryview of the full wire buffer.
    :param offset: byte offset of V within *wire*.
    :param length: byte length of V.
    :param offset_btl: byte offset of the TLV's T field within *wire*
                       (used by NameField to pass to ``Name.decode``).
    :param ignore_critical: forwarded to nested ``tlv_parse`` calls.
    :return: the parsed Python value.
    """
    kind = spec.kind
    if kind == 'bool':
        return True

    if kind == 'uint':
        if length == 1:
            raw = struct.unpack_from('!B', wire, offset)[0]
        elif length == 2:
            raw = struct.unpack_from('!H', wire, offset)[0]
        elif length == 4:
            raw = struct.unpack_from('!I', wire, offset)[0]
        elif length == 8:
            raw = struct.unpack_from('!Q', wire, offset)[0]
        else:
            raise ValueError(
                f'{fname}: uint value length must be 1, 2, 4, or 8; got {length}')
        # Auto-convert to the annotated Enum/Flag type if applicable
        if spec.enum_cls is not None:
            try:
                return spec.enum_cls(raw)
            except ValueError:
                pass
        return raw

    if kind == 'bytes':
        return wire[offset:offset + length]     # zero-copy memoryview slice

    if kind == 'str':
        return bytes(wire[offset:offset + length]).decode('utf-8')

    if kind == 'name':
        return Name.decode(wire, offset_btl)[0]

    if kind == 'model':
        ignore = spec.metadata.get('ignore_critical', ignore_critical)
        return tlv_parse(spec.annotation, wire[offset:offset + length], ignore)

    raise TypeError(f'Unknown kind {kind!r} for {fname!r}')


def tlv_parse(cls, wire, ignore_critical: bool = False, markers: dict = None):
    """
    Parse a TLV-encoded buffer into a fresh dataclass instance.

    Matching follows NDN ordering rules — fields are matched in their
    declaration order within *cls* (parent class fields come first, as per
    standard Python dataclass inheritance).

    Unknown critical TLV types (odd type numbers) raise
    :exc:`~ndn.encoding.DecodeError` unless *ignore_critical* is ``True``.

    Bytes-typed fields (``bytes``, ``bytearray``, ``memoryview`` annotations)
    are returned as zero-copy :class:`memoryview` slices into *wire*.

    :param cls: dataclass class to parse into.
    :param wire: TLV-encoded buffer
                 (:class:`bytes`, :class:`bytearray`, or :class:`memoryview`).
    :param ignore_critical: suppress :exc:`DecodeError` for unknown critical
                            TLV types.
    :param markers: optional dict for out-of-band state (offset_marker positions,
                    sig/digest buffers).  A fresh ``{}`` is used when ``None``.
    :return: populated dataclass instance.
    :raises DecodeError: unknown critical TLV type encountered.
    """
    if markers is None:
        markers = {}

    # Wrap in memoryview for zero-copy slicing throughout the parse
    if isinstance(wire, memoryview):
        mv = wire
    else:
        mv = memoryview(wire if isinstance(wire, (bytes, bytearray)) else bytes(wire))

    ordered = _get_schema(cls)

    obj = _make_default_instance(cls)
    offset = 0
    field_pos = 0                               # lowest index still eligible for matching

    while offset < len(mv):
        offset_btl = offset
        typ, sz_t = parse_tl_num(mv, offset)
        offset += sz_t
        length, sz_l = parse_tl_num(mv, offset)
        offset += sz_l
        if length > len(mv) - offset:
            raise IndexError('TLV length exceeds the input buffer')

        found = False
        for i in range(field_pos, len(ordered)):
            spec = ordered[i]
            kind = spec.kind
            if kind == 'offset_marker':
                continue                        # never matches a wire TLV type

            if spec.tlv_type != typ:
                continue

            fname = spec.name
            # Advance any offset_markers between field_pos and i.
            for j in range(field_pos, i):
                if ordered[j].kind == 'offset_marker':
                    markers[ordered[j].name] = offset_btl

            if kind == 'repeated':
                val = _parse_value(fname, spec.elem,
                                   mv, offset, length, offset_btl, ignore_critical)
                lst = getattr(obj, fname)
                if lst is None:
                    lst = []
                    object.__setattr__(obj, fname, lst)
                lst.append(val)
                field_pos = i                   # stay at i to accept more elements

            elif kind == 'map':
                # Two-phase parse: consume key, then immediately read value TLV.
                dct = getattr(obj, fname)
                if dct is None:
                    dct = {}
                    object.__setattr__(obj, fname, dct)
                idx = len(dct)

                key = _parse_value(f'{fname}[{idx}#k]', spec.key,
                                   mv, offset, length, offset_btl, ignore_critical)

                # advance past key value → now at the value TLV
                offset += length
                offset_btl = offset
                _val_typ, _sz_t2 = parse_tl_num(mv, offset)
                offset += _sz_t2
                length, _sz_l2 = parse_tl_num(mv, offset)
                offset += _sz_l2
                if _val_typ != spec.val.tlv_type:
                    raise DecodeError(
                        f'{fname}: expected map value type {spec.val.tlv_type:#x}, got {_val_typ:#x}')
                if length > len(mv) - offset:
                    raise IndexError('map value length exceeds the input buffer')

                val = _parse_value(f'{fname}[{idx}#v]', spec.val,
                                   mv, offset, length, offset_btl, ignore_critical)
                dct[key] = val
                field_pos = i                   # stay at i to accept more pairs

            elif kind == 'sig_value':
                # Extract sig buffer; append covered region to ##sig_covered_part.
                sig_buf = mv[offset:offset + length]
                markers['##sig_value_buf'] = sig_buf
                cover_start_field = spec.metadata.get('cover_start')
                if cover_start_field is not None:
                    cover_start = markers.get(cover_start_field)
                    if cover_start is not None:
                        markers.setdefault('##sig_covered_part', []).append(
                            mv[cover_start:offset_btl])
                object.__setattr__(obj, fname, sig_buf)
                field_pos = i + 1

            elif kind == 'interest_name':
                # Decode name; split into sig-covered components and digest buf.
                name = Name.decode(mv, offset_btl)[0]
                sig_cp = markers.setdefault('##sig_covered_part', [])
                for comp in name:
                    if Component.get_type(comp) == Component.TYPE_PARAMETERS_SHA256:
                        markers['##digest_buf'] = Component.get_value(comp)
                    else:
                        sig_cp.append(comp)
                object.__setattr__(obj, fname, name)
                field_pos = i + 1

            else:
                val = _parse_value(fname, spec,
                                   mv, offset, length, offset_btl, ignore_critical)
                object.__setattr__(obj, fname, val)
                field_pos = i + 1

            found = True
            break

        if not found and (typ & 1) and not ignore_critical:
            raise DecodeError(
                f'unknown critical TLV type {typ:#x} is unrecognized, '
                f'redundant, or out-of-order')

        offset += length

    return obj


# ---------------------------------------------------------------------------
# Marker helpers (convenience wrappers for the markers dict)
# ---------------------------------------------------------------------------

def tlv_get_arg(markers: dict, key: str, default=None):
    """
    Read a value from the *markers* dict used by :func:`tlv_encode` /
    :func:`tlv_parse`.

    Equivalent to ``markers.get(key, default)``.
    """
    return markers.get(key, default)


def tlv_set_arg(markers: dict, key: str, val) -> None:
    """
    Write a value into the *markers* dict used by :func:`tlv_encode` /
    :func:`tlv_parse`.

    Equivalent to ``markers[key] = val``.
    """
    markers[key] = val
