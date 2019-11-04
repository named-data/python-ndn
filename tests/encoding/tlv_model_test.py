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
from ndn.encoding import TlvModel, NameField, UintField, BytesField, BoolField, Component,\
    RepeatedField, ModelField, Name, IncludeBase


class TestEncodeDecode:
    def test_basic(self):
        class Model(TlvModel):
            name = NameField()
            int_val = UintField(0x03)
            str_val = BytesField(0x02)
            bool_val = BoolField(0x01)

        model = Model()
        model.name = ['test', Component.from_str('name')]
        model.int_val = 0
        assert model.encode() == b'\x07\x0c\x08\x04test\x08\x04name\x03\x01\x00'

        model = Model.parse(b'\x07\x0c\x08\x04test\x08\x04name\x03\x01\x00')
        assert model.name == Name.from_str('/test/name')
        assert model.int_val == 0
        assert not model.bool_val

        model.name = 'test/name'
        model.str_val = b'str'
        model.bool_val = True
        assert model.encode() == b'\x07\x0c\x08\x04test\x08\x04name\x03\x01\x00\x02\x03str\x01\x00'

        model = Model.parse(b'\x07\x0c\x08\x04test\x08\x04name\x03\x01\x00\x02\x03str\x01\x00')
        assert model.str_val == b'str'
        assert model.bool_val

    def test_repeat(self):
        class WordArray(TlvModel):
            words = RepeatedField(UintField(0x01, fixed_len=2))

        array = WordArray()
        array.words = [i for i in range(3)]
        assert array.encode() == b'\x01\x02\x00\x00\x01\x02\x00\x01\x01\x02\x00\x02'

        array = WordArray.parse(b'\x01\x02\x00\x00\x01\x02\x00\x01\x01\x02\x00\x02')
        assert array.words == [0, 1, 2]

    def test_nested(self):
        class Inner(TlvModel):
            val = UintField(0x01)

        class Outer(TlvModel):
            val = ModelField(0x02, Inner)

        obj = Outer()
        obj.val = Inner()
        obj.val.val = 255
        assert obj.encode() == b'\x02\x03\x01\x01\xFF'

        obj = Outer.parse(b'\x02\x03\x01\x01\xFF')
        assert obj.val.val == 255

    def test_derivation(self):
        class Base(TlvModel):
            m2 = UintField(0x02)

        class Derived(Base):
            m1 = UintField(0x01)
            _base = IncludeBase(Base)
            m3 = UintField(0x03)

        obj = Derived()
        obj.m1, obj.m2, obj.m3 = range(1, 4)
        assert obj.encode() == b'\x01\x01\x01\x02\x01\x02\x03\x01\x03'

        obj = Derived.parse(b'\x01\x01\x01\x02\x01\x02\x03\x01\x03')
        assert obj.m1 == 1
        assert obj.m2 == 2
        assert obj.m3 == 3

    def test_override(self):
        class A1(TlvModel):
            m1 = UintField(0x01)

        class A2(A1):
            _a1 = IncludeBase(A1)
            m2 = UintField(0x02)

        class B1(TlvModel):
            a = ModelField(0x03, A1)

        class B2(B1):
            IncludeBase(B1)
            a = ModelField(0x03, A2)

        obj = B2()
        obj.a = A2()
        obj.a.m1 = 1
        obj.a.m2 = 2
        assert obj.encode() == b'\x03\x06\x01\x01\x01\x02\x01\x02'

        obj = B2.parse(b'\x03\x06\x01\x01\x01\x02\x01\x02')
        assert obj.a.m1 == 1
        assert obj.a.m2 == 2

    def test_diamond(self):
        class A(TlvModel):
            m1 = UintField(0x01)

        class B1(A):
            _base = IncludeBase(A)
            m1 = UintField(0x02)
            m4 = UintField(0x04)

        class B2(A):
            _base = IncludeBase(A)
            m1 = UintField(0x03)
            m5 = UintField(0x05)

        class D(B1, B2):
            _b2 = IncludeBase(B2)
            _b1 = IncludeBase(B1)

        obj = D()
        obj.m1, obj.m2, obj.m4, obj.m5 = 1, 2, 4, 5
        assert obj.encode() == b'\x02\x01\x01\x05\x01\x05\x04\x01\x04'

        obj = D.parse(b'\x02\x01\x01\x05\x01\x05\x04\x01\x04')
        assert obj.m1 == 1
        assert obj.m4 == 4
        assert obj.m5 == 5


class TestAsDict:
    def test_asdict(self):
        class WordArray(TlvModel):
            words = RepeatedField(UintField(0x04, fixed_len=2))

        class Model(TlvModel):
            name = NameField()
            int_val = UintField(0x03)
            str_val = BytesField(0x02)
            bool_val = BoolField(0x01)
            array = ModelField(0x05, WordArray)

        obj = Model()
        obj.name = '/test/name'
        obj.int_val = 0
        obj.str_val = b'\x00'
        obj.array = WordArray()
        obj.array.words = [1, 2, 3]
        assert obj.asdict() == {'name': '/test/name',
                                'int_val': 0,
                                'str_val': b'\x00',
                                'bool_val': None,
                                'array': {'words': [1, 2, 3]}}
