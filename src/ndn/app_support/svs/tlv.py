# -----------------------------------------------------------------------------
# Copyright (C) 2023-2023 The python-ndn authors
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
from ... import encoding as enc


__all__ = ['StateVecEntry', 'StateVec', 'StateVecWrapper', 'MappingEntry', 'MappingData', 'MappingDataWrapper']


class StateVecEntry(enc.TlvModel):
    node_id = enc.NameField()
    seq_no = enc.UintField(0xcc)


class StateVec(enc.TlvModel):
    entries = enc.RepeatedField(enc.ModelField(0xca, StateVecEntry))


class StateVecWrapper(enc.TlvModel):
    val = enc.ModelField(0xc9, StateVec)


class MappingEntry(enc.TlvModel):
    seq_no = enc.UintField(0xcc)
    app_name = enc.NameField()


class MappingData(enc.TlvModel):
    node_id = enc.NameField()
    entries = enc.ModelField(0xce, MappingEntry)


class MappingDataWrapper(enc.TlvModel):
    val = enc.ModelField(0xcd, MappingEntry)
