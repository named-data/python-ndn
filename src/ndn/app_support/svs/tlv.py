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
import dataclasses as dc
from ... import encoding as enc


__all__ = ['StateVecEntry', 'StateVec', 'StateVecWrapper', 'MappingEntry', 'MappingData', 'MappingDataWrapper']


@dc.dataclass
class StateVecEntry:
    node_id: enc.NDNName = enc.tlv_field(enc.Name.TYPE_NAME, default=None)
    seq_no: int | None = enc.tlv_field(0xcc, default=None)


@dc.dataclass
class StateVec:
    entries: list[StateVecEntry] = enc.tlv_field(0xca, default_factory=list)


@dc.dataclass
class StateVecWrapper:
    val: StateVec | None = enc.tlv_field(0xc9, default=None)


@dc.dataclass
class MappingEntry:
    seq_no: int | None = enc.tlv_field(0xcc, default=None)
    app_name: enc.NDNName = enc.tlv_field(enc.Name.TYPE_NAME, default=None)


@dc.dataclass
class MappingData:
    node_id: enc.NDNName = enc.tlv_field(enc.Name.TYPE_NAME, default=None)
    entries: MappingEntry | None = enc.tlv_field(0xce, default=None)


@dc.dataclass
class MappingDataWrapper:
    val: MappingEntry | None = enc.tlv_field(0xcd, default=None)
