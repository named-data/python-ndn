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
import collections
import sqlite3
from typing import Iterator
from dataclasses import dataclass
from typing import Dict, Any
from ...encoding import FormalName, BinaryStr, NonStrictName, Name
from ..signer.sha256_digest_signer import DigestSha256Signer
from ..tpm.tpm import Tpm
from .keychain import Keychain


@dataclass
class Certificate:
    id: int
    key: FormalName
    name: FormalName
    data: BinaryStr
    is_default: bool


class Key(collections.abc.Mapping):
    row_id: int
    identity: FormalName
    name: FormalName
    key_bits: BinaryStr
    is_default: bool

    def __init__(self, pib, identity, row_id, name, key_bits, is_default):
        self.pib = pib
        self.identity = identity
        self.row_id = row_id
        self.name = name
        self.key_bits = key_bits
        self.is_default = is_default

    def __len__(self) -> int:
        cursor = self.pib.conn.execute('SELECT count(*) FROM keys WHERE identity_id=?', (self.row_id,))
        ret = cursor.fetchone()[0]
        cursor.close()
        return ret

    def __getitem__(self, name: NonStrictName) -> Certificate:
        name = Name.to_bytes(name)
        sql = 'SELECT id, certificate_name, certificate_data, is_default FROM certificates WHERE certificate_name=?'
        cursor = self.pib.conn.execute(sql, (name,))
        data = cursor.fetchone()
        if not data:
            raise KeyError(name)
        row_id, cert_name, cert_data, is_default = data
        cursor.close()
        return Certificate(id=row_id, key=self.name, name=cert_name, data=cert_data, is_default=is_default != 0)

    def __iter__(self) -> Iterator[FormalName]:
        cursor = self.pib.conn.execute('SELECT certificate_name FROM certificates WHERE key_id=?', (self.row_id,))
        while True:
            name = cursor.fetchone()
            if not name:
                break
            yield Name.from_bytes(name[0])
        cursor.close()

    def del_cert(self, name: NonStrictName):
        return self.pib.del_certificate(name)

    def has_default_cert(self) -> bool:
        cursor = self.pib.conn.execute('SELECT id FROM certificates WHERE is_default=1 AND key_id=?', (self.row_id,))
        ret = cursor.fetchone() is not None
        cursor.close()
        return ret

    def set_default_cert(self, name: NonStrictName):
        name = Name.to_bytes(name)
        self.pib.conn.execute('UPDATE certificates SET is_default=1 WHERE certificate_name=?', (name,))
        self.pib.conn.commit()

    def default_cert(self) -> Certificate:
        sql = ('SELECT id, certificate_name, certificate_data, is_default '
               'FROM certificates WHERE is_default=1 AND key_id=?')
        cursor = self.pib.conn.execute(sql, (self.row_id,))
        data = cursor.fetchone()
        if not data:
            raise KeyError('No default certificate')
        row_id, cert_name, cert_data, is_default = data
        cursor.close()
        return Certificate(id=row_id, key=self.name, name=cert_name, data=cert_data, is_default=is_default != 0)


class Identity(collections.abc.Mapping):
    row_id: int
    name: FormalName
    is_default: bool

    def __init__(self, pib, row_id, name, is_default):
        self.pib = pib
        self.row_id = row_id
        self.name = name
        self.is_default = is_default

    def __len__(self) -> int:
        cursor = self.pib.conn.execute('SELECT count(*) FROM keys WHERE identity_id=?', (self.row_id,))
        ret = cursor.fetchone()[0]
        cursor.close()
        return ret

    def __getitem__(self, name: NonStrictName) -> Key:
        name = Name.to_bytes(name)
        cursor = self.pib.conn.execute('SELECT id, key_name, key_bits, is_default FROM keys WHERE key_name=?',
                                       (name,))
        data = cursor.fetchone()
        if not data:
            raise KeyError(name)
        row_id, key_name, key_bits, is_default = data
        cursor.close()
        return Key(self.pib, self.name, row_id, Name.from_bytes(key_name), key_bits, is_default != 0)

    def __iter__(self) -> Iterator[FormalName]:
        cursor = self.pib.conn.execute('SELECT key_name FROM keys WHERE identity_id=?', (self.row_id,))
        while True:
            name = cursor.fetchone()
            if not name[0]:
                break
            yield Name.from_bytes(name)
        cursor.close()

    def del_key(self, name: NonStrictName):
        return self.pib.del_key(name)

    def new_key(self) -> Key:
        return self.pib.new_key(self.name)

    def has_default_key(self) -> bool:
        cursor = self.pib.conn.execute('SELECT id FROM keys WHERE is_default=1 AND identity_id=?', (self.row_id,))
        ret = cursor.fetchone() is not None
        cursor.close()
        return ret

    def set_default_key(self, name: NonStrictName):
        name = Name.to_bytes(name)
        self.pib.conn.execute('UPDATE keys SET is_default=1 WHERE key_name=?', (name,))
        self.pib.conn.commit()

    def default_key(self) -> Key:
        sql = 'SELECT id, key_name, key_bits, is_default FROM keys WHERE is_default=1 AND identity_id=?'
        cursor = self.pib.conn.execute(sql, (self.row_id,))
        data = cursor.fetchone()
        if not data:
            raise KeyError('No default key')
        row_id, key_name, key_bits, is_default = data
        cursor.close()
        return Key(self.pib, self.name, row_id, Name.from_bytes(key_name), key_bits, is_default != 0)


class KeychainSqlite3(Keychain):
    # __getitem__ will be called extra times, but there is no need to optimize for performance
    tpm: Tpm
    tpm_locator: str
    _signer_cache: dict

    def __init__(self, path: str, tpm: Tpm):
        self.conn = sqlite3.connect(path)
        cursor = self.conn.execute('SELECT tpm_locator FROM tpmInfo')
        self.tpm_locator = cursor.fetchone()[0]
        cursor.close()
        self.tpm = tpm
        self._signer_cache = {}

    def __iter__(self) -> Iterator[FormalName]:
        cursor = self.conn.execute('SELECT identity FROM identities')
        while True:
            name = cursor.fetchone()
            if not name:
                break
            yield Name.from_bytes(name[0])
        cursor.close()

    def __len__(self) -> int:
        cursor = self.conn.execute('SELECT count(*) FROM identities')
        ret = cursor.fetchone()[0]
        cursor.close()
        return ret

    def __getitem__(self, name: NonStrictName) -> Identity:
        name = Name.to_bytes(name)
        cursor = self.conn.execute('SELECT id, identity, is_default FROM identities WHERE identity=?', (name,))
        data = cursor.fetchone()
        if not data:
            raise KeyError(name)
        row_id, identity, is_default = data
        cursor.close()
        return Identity(self, row_id, Name.from_bytes(identity), is_default != 0)

    def has_default_identity(self) -> bool:
        cursor = self.conn.execute('SELECT id FROM identities WHERE is_default=1')
        ret = cursor.fetchone() is not None
        cursor.close()
        return ret

    def set_default_identity(self, name: NonStrictName):
        name = Name.to_bytes(name)
        self.conn.execute('UPDATE identities SET is_default=1 WHERE identity=?', (name,))
        self.conn.commit()

    def default_identity(self) -> Identity:
        cursor = self.conn.execute('SELECT id, identity, is_default FROM identities WHERE is_default=1')
        data = cursor.fetchone()
        if not data:
            raise KeyError('No default identity')
        row_id, identity, is_default = data
        cursor.close()
        return Identity(self, row_id, Name.from_bytes(identity), is_default != 0)

    def new_identity(self, name: NonStrictName) -> Identity:
        name = Name.to_bytes(name)
        if name not in self:
            self.conn.execute('INSERT INTO identities (identity) values (?)', (name,))
            self.conn.commit()
        if not self.has_default_identity():
            self.set_default_identity(name)
        return self[name]

    def shutdown(self):
        self.conn.close()

    def del_identity(self, name: NonStrictName):
        name = Name.to_bytes(name)
        self.conn.execute('DELETE FROM identities WHERE identity=?', (name,))
        self.conn.commit()

    def get_signer(self, sign_args: Dict[str, Any]):
        if sign_args.pop('no_signature', False):
            return None
        if sign_args.pop('digest_sha256', False):
            return DigestSha256Signer()
        key_name = sign_args.pop('key', None)
        if not key_name:
            id_name = sign_args.pop('identity', None)
            if id_name:
                if isinstance(id_name, Identity):
                    identity = id_name
                else:
                    identity = self[id_name]
            else:
                identity = self.default_identity()
            key_name = identity.default_key().name
        elif isinstance(key_name, Key):
            key_name = key_name.name
        key_name_bytes = Name.to_bytes(key_name)
        signer = self._signer_cache.get(key_name_bytes, None)
        if not signer:
            signer = self.tpm.get_signer(key_name)
            self._signer_cache[key_name_bytes] = signer
        return signer

    def new_key(self, id_name: NonStrictName) -> Key:
        # TODO: implement missing functions
        pass

    def del_key(self, name: NonStrictName):
        pass

    def del_cert(self, name: NonStrictName):
        pass
