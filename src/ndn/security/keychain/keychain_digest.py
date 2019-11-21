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
from .keychain import Keychain
from typing import Dict, Any
from ..signer.sha256_digest_signer import DigestSha256Signer


class KeychainDigest(Keychain):
    """
    A signer which has no Identity and always returns a SHA-256 digest signer.
    """
    def get_signer(self, sign_args: Dict[str, Any]):
        if sign_args.pop('no_signature', False):
            return None
        else:
            return DigestSha256Signer()

    def __iter__(self):
        return None

    def __len__(self) -> int:
        return 0

    def __getitem__(self, name):
        raise KeyError(name)
