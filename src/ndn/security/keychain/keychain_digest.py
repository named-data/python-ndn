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
from .keychain import Keychain
from typing import Dict, Any
from ..signer.sha256_digest_signer import DigestSha256Signer


class KeychainDigest(Keychain):
    """
    A signer which has no Identity and always returns a SHA-256 digest signer.
    """
    def get_signer(self, sign_args: Dict[str, Any]):
        if sign_args.get('no_signature', False):
            return None
        else:
            return DigestSha256Signer()

    def __iter__(self):
        return None

    def __len__(self) -> int:
        return 0

    def __getitem__(self, name):
        raise KeyError(name)
