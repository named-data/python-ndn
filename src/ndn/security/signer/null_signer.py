# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
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
from typing import List
from ...encoding import Signer, SignatureType, VarBinaryStr


class NullSigner(Signer):
    def write_signature_info(self, signature_info):
        signature_info.signature_type = SignatureType.NULL
        signature_info.key_locator = None

    def get_signature_value_size(self):
        return 0

    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]) -> int:
        wire[:] = b''
        return 0
