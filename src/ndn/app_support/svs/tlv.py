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
from typing import Optional
from ... import encoding as enc


__all__ = ['StateVecEntry', 'StateVec', 'StateVecWrapper', 'MappingEntry', 'MappingData', 'MappingDataWrapper']


@dc.dataclass
class StateVecEntry:
    node_id: enc.NDNName = dc.field(default=None, metadata={'tlv_type': enc.Name.TYPE_NAME})
    seq_no: Optional[int] = dc.field(default=None, metadata={'tlv_type': 0xcc})


@dc.dataclass
class StateVec:
    entries: list[StateVecEntry] = dc.field(default_factory=list, metadata={'tlv_type': 0xca})


@dc.dataclass
class StateVecWrapper:
    val: Optional[StateVec] = dc.field(default=None, metadata={'tlv_type': 0xc9})


@dc.dataclass
class MappingEntry:
    seq_no: Optional[int] = dc.field(default=None, metadata={'tlv_type': 0xcc})
    app_name: enc.NDNName = dc.field(default=None, metadata={'tlv_type': enc.Name.TYPE_NAME})


@dc.dataclass
class MappingData:
    node_id: enc.NDNName = dc.field(default=None, metadata={'tlv_type': enc.Name.TYPE_NAME})
    entries: Optional[MappingEntry] = dc.field(default=None, metadata={'tlv_type': 0xce})


@dc.dataclass
class MappingDataWrapper:
    val: Optional[MappingEntry] = dc.field(default=None, metadata={'tlv_type': 0xcd})
