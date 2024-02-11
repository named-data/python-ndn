# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
from __future__ import annotations
import logging
import os
import sqlite3
from typing import Iterator, Any
from ...encoding import FormalName, BinaryStr, NonStrictName, Name
from ...app_support.security_v2 import self_sign
from ..signer.sha256_digest_signer import DigestSha256Signer
from ..tpm.tpm import Tpm
from .keychain import Keychain, AbstractCertificate, AbstractKey, AbstractIdentity


INITIALIZE_SQL = """
CREATE TABLE IF NOT EXISTS
  tpmInfo(
    tpm_locator           BLOB
  );
CREATE TABLE IF NOT EXISTS
  identities(
    id                    INTEGER PRIMARY KEY,
    identity              BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  identityIndex ON identities(identity);
CREATE TRIGGER IF NOT EXISTS
  identity_default_before_insert_trigger
  BEFORE INSERT ON identities
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE identities SET is_default=0;
  END;
CREATE TRIGGER IF NOT EXISTS
  identity_default_after_insert_trigger
  AFTER INSERT ON identities
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM identities
       WHERE is_default=1)
  BEGIN
    UPDATE identities
      SET is_default=1
      WHERE identity=NEW.identity;
  END;
CREATE TRIGGER IF NOT EXISTS
  identity_default_update_trigger
  BEFORE UPDATE ON identities
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE identities SET is_default=0;
  END;
CREATE TABLE IF NOT EXISTS
  keys(
    id                    INTEGER PRIMARY KEY,
    identity_id           INTEGER NOT NULL,
    key_name              BLOB NOT NULL,
    key_bits              BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0,
    FOREIGN KEY(identity_id)
      REFERENCES identities(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  keyIndex ON keys(key_name);
CREATE TRIGGER IF NOT EXISTS
  key_default_before_insert_trigger
  BEFORE INSERT ON keys
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE keys
      SET is_default=0
      WHERE identity_id=NEW.identity_id;
  END;
CREATE TRIGGER IF NOT EXISTS
  key_default_after_insert_trigger
  AFTER INSERT ON keys
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM keys
       WHERE is_default=1
         AND identity_id=NEW.identity_id)
  BEGIN
    UPDATE keys
      SET is_default=1
      WHERE key_name=NEW.key_name;
  END;
CREATE TRIGGER IF NOT EXISTS
  key_default_update_trigger
  BEFORE UPDATE ON keys
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE keys
      SET is_default=0
      WHERE identity_id=NEW.identity_id;
  END;
CREATE TABLE IF NOT EXISTS
  certificates(
    id                    INTEGER PRIMARY KEY,
    key_id                INTEGER NOT NULL,
    certificate_name      BLOB NOT NULL,
    certificate_data      BLOB NOT NULL,
    is_default            INTEGER DEFAULT 0,
    FOREIGN KEY(key_id)
      REFERENCES keys(id)
      ON DELETE CASCADE
      ON UPDATE CASCADE
  );
CREATE UNIQUE INDEX IF NOT EXISTS
  certIndex ON certificates(certificate_name);
CREATE TRIGGER IF NOT EXISTS
  cert_default_before_insert_trigger
  BEFORE INSERT ON certificates
  FOR EACH ROW
  WHEN NEW.is_default=1
  BEGIN
    UPDATE certificates
      SET is_default=0
      WHERE key_id=NEW.key_id;
  END;
CREATE TRIGGER IF NOT EXISTS
  cert_default_after_insert_trigger
  AFTER INSERT ON certificates
  FOR EACH ROW
  WHEN NOT EXISTS
    (SELECT id
       FROM certificates
       WHERE is_default=1
         AND key_id=NEW.key_id)
  BEGIN
    UPDATE certificates
      SET is_default=1
      WHERE certificate_name=NEW.certificate_name;
  END;
CREATE TRIGGER IF NOT EXISTS
  cert_default_update_trigger
  BEFORE UPDATE ON certificates
  FOR EACH ROW
  WHEN NEW.is_default=1 AND OLD.is_default=0
  BEGIN
    UPDATE certificates
      SET is_default=0
      WHERE key_id=NEW.key_id;
  END;
"""


class Certificate(AbstractCertificate):
    """
    A dataclass for a Certificate.

    :ivar id: its id in the database.
    :vartype id: int
    :ivar key: the Name of the associated Key.
    :vartype key: :any:`FormalName`
    :ivar name: its Name.
    :vartype name: :any:`FormalName`
    :ivar data: the content.
    :vartype data: bytes
    :ivar is_default: whether this is the default Identity.
    :vartype is_default: bool
    """
    id: int
    _key: FormalName
    _name: FormalName
    _data: BinaryStr
    is_default: bool

    @property
    def name(self) -> FormalName:
        return self._name

    @property
    def key(self) -> FormalName:
        return self._key

    @property
    def data(self) -> BinaryStr:
        return self._data

    def __init__(self, row_id: int, key: FormalName, name: FormalName, data: BinaryStr, is_default: bool):
        self.id = row_id
        self._key = key
        self._name = name
        self._data = data
        self.is_default = is_default


class Key(AbstractKey):
    """
    A Key. It behaves like an immutable ``dict`` from :any:`FormalName` to :any:`Certificate`.

    :ivar row_id: its id in the database.
    :vartype row_id: int
    :ivar identity: the Name of the associated Identity.
    :vartype identity: :any:`FormalName`.
    :ivar name: its Name.
    :vartype name: :any:`FormalName`
    :ivar key_bits: the key bits of the public key.
    :vartype key_bits: bytes
    :ivar is_default: whether this is the default Identity.
    :vartype is_default: bool
    """
    row_id: int
    _identity: FormalName
    _name: FormalName
    _key_bits: BinaryStr
    is_default: bool

    @property
    def key_bits(self) -> BinaryStr:
        return self._key_bits

    @property
    def name(self) -> FormalName:
        return self._name

    @property
    def identity(self) -> FormalName:
        return self._identity

    def __init__(self, pib, identity, row_id, name, key_bits, is_default):
        self.pib = pib
        self._identity = identity
        self.row_id = row_id
        self._name = name
        self._key_bits = key_bits
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
        return Certificate(row_id=row_id, key=self._name, name=cert_name, data=cert_data, is_default=is_default != 0)

    def __iter__(self) -> Iterator[FormalName]:
        cursor = self.pib.conn.execute('SELECT certificate_name FROM certificates WHERE key_id=?', (self.row_id,))
        while True:
            name = cursor.fetchone()
            if not name:
                break
            yield Name.from_bytes(name[0])
        cursor.close()

    def del_cert(self, name: NonStrictName):
        """
        Delete a specific Certificare.

        :param name: the Name of the Key to delete.
        :type name: :any:`NonStrictName`
        """
        return self.pib.del_certificate(name)

    def has_default_cert(self) -> bool:
        """
        Whether it has a default Certificate.

        :return: ``True`` if there is one.
        """
        cursor = self.pib.conn.execute('SELECT id FROM certificates WHERE is_default=1 AND key_id=?', (self.row_id,))
        ret = cursor.fetchone() is not None
        cursor.close()
        return ret

    def set_default_cert(self, name: NonStrictName):
        """
        Set the default Certificate.

        :param name: the Name of the new default Certificate.
        :type name: :any:`NonStrictName`
        """
        name = Name.to_bytes(name)
        self.pib.conn.execute('UPDATE certificates SET is_default=1 WHERE certificate_name=?', (name,))
        self.pib.conn.commit()

    def default_cert(self) -> Certificate:
        """
        Get the default Certificate.

        :return: the default Certificate.
        """
        sql = ('SELECT id, certificate_name, certificate_data, is_default '
               'FROM certificates WHERE is_default=1 AND key_id=?')
        cursor = self.pib.conn.execute(sql, (self.row_id,))
        data = cursor.fetchone()
        if not data:
            raise KeyError('No default certificate')
        row_id, cert_name, cert_data, is_default = data
        cursor.close()
        return Certificate(row_id=row_id, key=self._name, name=cert_name, data=cert_data, is_default=is_default != 0)


class Identity(AbstractIdentity):
    """
    An Identity. It behaves like an immutable ``dict`` from :any:`FormalName` to :any:`Key`.

    :ivar row_id: its id in the database.
    :vartype row_id: int
    :ivar name: its Name.
    :vartype name: :any:`FormalName`
    :ivar is_default: whether this is the default Identity.
    :vartype is_default: bool
    """
    row_id: int
    _name: FormalName
    is_default: bool

    @property
    def name(self) -> FormalName:
        return self._name

    def __init__(self, pib, row_id, name, is_default):
        self.pib = pib
        self.row_id = row_id
        self._name = name
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
        return Key(self.pib, self._name, row_id, Name.from_bytes(key_name), key_bits, is_default != 0)

    def __iter__(self) -> Iterator[FormalName]:
        cursor = self.pib.conn.execute('SELECT key_name FROM keys WHERE identity_id=?', (self.row_id,))
        while True:
            name = cursor.fetchone()
            if not name:
                break
            yield Name.from_bytes(name[0])
        cursor.close()

    def del_key(self, name: NonStrictName):
        """
        Delete a specific Key.

        :param name: the Name of the Key to delete.
        :type name: :any:`NonStrictName`
        """
        return self.pib.del_key(name)

    def new_key(self, key_type: str) -> Key:
        """
        Create a new key with default arguments.

        :param key_type: the type of the Key. Can be ``ec`` or ``rsa``.
        :return: the new Key.
        """
        return self.pib.new_key(self._name, key_type=key_type)

    def has_default_key(self) -> bool:
        """
        Whether it has a default Key.

        :return: ``True`` if there is one.
        """
        cursor = self.pib.conn.execute('SELECT id FROM keys WHERE is_default=1 AND identity_id=?', (self.row_id,))
        ret = cursor.fetchone() is not None
        cursor.close()
        return ret

    def set_default_key(self, name: NonStrictName):
        """
        Set the default Key.

        :param name: the Name of the new default Key.
        :type name: :any:`NonStrictName`
        """
        name = Name.to_bytes(name)
        self.pib.conn.execute('UPDATE keys SET is_default=1 WHERE key_name=?', (name,))
        self.pib.conn.commit()

    def default_key(self) -> Key:
        """
        Get the default Key.

        :return: the default Key.
        """
        sql = 'SELECT id, key_name, key_bits, is_default FROM keys WHERE is_default=1 AND identity_id=?'
        cursor = self.pib.conn.execute(sql, (self.row_id,))
        data = cursor.fetchone()
        if not data:
            raise KeyError('No default key')
        row_id, key_name, key_bits, is_default = data
        cursor.close()
        return Key(self.pib, self._name, row_id, Name.from_bytes(key_name), key_bits, is_default != 0)


class KeychainSqlite3(Keychain):
    r"""
    Store public infomation in a Sqlite3 database and private keys in a TPM.

    :ivar path: the path to the database. The default path is ``~/.ndn/pib.db``.
    :vartype path: str
    :ivar tpm: an instance of TPM.
    :vartype tpm: :class:`Tpm`
    :ivar tpm_locator: a URI string describing the location of TPM.
    :vartype tpm_locator: str
    """
    tpm: Tpm
    path: str
    tpm_locator: str
    _signer_cache: dict

    @staticmethod
    def initialize(path: str, tpm_scheme: str, tpm_path: str = '') -> bool:
        if os.path.exists(path):
            logging.getLogger(__name__).fatal(f'PIB database {path} already exists.')
            return False
        # Make sure the directory exists
        base_dir = os.path.dirname(path)
        os.makedirs(base_dir, exist_ok=True)
        # Create an empty folder if the scheme is file
        if tpm_scheme == 'tpm-file':
            if not tpm_path:
                tpm_path = os.path.join(base_dir, 'ndnsec-key-file')
            os.makedirs(tpm_path, exist_ok=True)
        # Create sqlite3 database
        conn = sqlite3.connect(path)
        conn.executescript(INITIALIZE_SQL)
        conn.execute('INSERT INTO tpmInfo (tpm_locator) VALUES (?)', (f'{tpm_scheme}:{tpm_path}'.encode(),))
        conn.commit()
        conn.close()
        return True

    def __init__(self, path: str, tpm: Tpm):
        self.path = path
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
        """
        Whether there is a default Identity.
        :return: ``True`` if there is one.
        """
        cursor = self.conn.execute('SELECT id FROM identities WHERE is_default=1')
        ret = cursor.fetchone() is not None
        cursor.close()
        return ret

    def set_default_identity(self, name: NonStrictName):
        """
        Set the default Identity.

        :param name: the Name of the new default Identity.
        :type name: :any:`NonStrictName`
        """
        name = Name.to_bytes(name)
        self.conn.execute('UPDATE identities SET is_default=1 WHERE identity=?', (name,))
        self.conn.commit()

    def default_identity(self) -> Identity:
        """
        Get the default Identity.

        :return: the default Identity.
        """
        cursor = self.conn.execute('SELECT id, identity, is_default FROM identities WHERE is_default=1')
        data = cursor.fetchone()
        if not data:
            raise KeyError('No default identity')
        row_id, identity, is_default = data
        cursor.close()
        return Identity(self, row_id, Name.from_bytes(identity), is_default != 0)

    def new_identity(self, name: NonStrictName) -> Identity:
        """
        Create a new Identity without a default Key.
        This is used to control the Keychain in a fine-grained way.

        :param name: the Name of the new Identity.
        :type name: :any:`NonStrictName`
        :return: the Identity created.
        """
        name = Name.to_bytes(name)
        if name not in self:
            self.conn.execute('INSERT INTO identities (identity) VALUES (?)', (name,))
            self.conn.commit()
        else:
            raise KeyError(f'Identity {Name.to_str(name)} already exists')
        if not self.has_default_identity():
            self.set_default_identity(name)
        return self[name]

    def touch_identity(self, id_name: NonStrictName) -> Identity:
        """
        Get an Identity with specific name. Create a new one if it does not exist.
        The newly created one will automatically have a default ECC Key and self-signed Certificate.

        :param id_name: the Name of Identity.
        :type id_name: :any:`NonStrictName`
        :return: the specified Identity.
        """
        name = Name.to_bytes(id_name)
        if name not in self:
            self.conn.execute('INSERT INTO identities (identity) VALUES (?)', (name,))
            self.conn.commit()
            self.new_key(name)
        if not self.has_default_identity():
            self.set_default_identity(name)
        return self[name]

    def __del__(self):
        if self.conn is not None:
            self.shutdown()

    def shutdown(self):
        """
        Close the connection.
        """
        self.conn.close()
        self.conn = None

    def del_identity(self, name: NonStrictName):
        """
        Delete a specific Identity.

        :param name: the Identity Name.
        :type name: :any:`NonStrictName`
        """
        name = Name.to_bytes(name)
        for key_name in self[name]:
            self.del_key(key_name)
        self.conn.execute('DELETE FROM identities WHERE identity=?', (name,))
        self.conn.commit()
        self._signer_cache = {}

    def get_signer(self, sign_args: dict[str, Any]):
        if sign_args.get('no_signature', False):
            return None
        if sign_args.get('digest_sha256', False):
            return DigestSha256Signer()
        cert_name = sign_args.get('cert', None)
        if not cert_name:
            key_name = sign_args.get('key', None)
            if not key_name:
                id_name = sign_args.get('identity', None)
                if id_name:
                    if isinstance(id_name, Identity):
                        identity = id_name
                    else:
                        identity = self[id_name]
                else:
                    identity = self.default_identity()
                key = identity.default_key()
                cert_name = key.default_cert().name
                key_name = key.name
            elif isinstance(key_name, Key):
                cert_name = key_name.default_cert().name
                key_name = key_name.name
            else:
                id_name = key_name[:-2]
                cert_name = self[id_name][key_name].default_cert().name
        elif isinstance(cert_name, Certificate):
            cert_name = cert_name.name
            key_name = cert_name[:-2]
        else:
            key_name = cert_name[:-2]
        key_locator_name = sign_args.get('key_locator', None)
        if not key_locator_name:
            key_locator_name = cert_name
        key_locator_bytes = Name.to_bytes(key_locator_name)
        signer = self._signer_cache.get(key_locator_bytes, None)
        if not signer:
            signer = self.tpm.get_signer(key_name, key_locator_name)
            self._signer_cache[key_locator_bytes] = signer
        return signer

    def del_key(self, name: NonStrictName):
        """
        Delete a specific Key.

        :param name: the Key Name.
        :type name: :any:`NonStrictName`
        """
        formal_name = Name.normalize(name)
        name = Name.to_bytes(name)
        id_name = formal_name[:-2]
        key = self[id_name][formal_name]
        self.conn.execute('DELETE FROM certificates WHERE key_id=?', (key.row_id,))
        self.conn.execute('DELETE FROM keys WHERE key_name=?', (name,))
        self.conn.commit()
        self.tpm.delete_key(formal_name)
        self._signer_cache = {}

    def del_cert(self, name: NonStrictName):
        """
        Delete a specific Certificate.

        :param name: the Certificate Name.
        :type name: :any:`NonStrictName`
        """
        name = Name.to_bytes(name)
        self.conn.execute('DELETE FROM certificates WHERE certificate_name=?', (name,))
        self.conn.commit()
        self._signer_cache = {}

    def new_key(self, id_name: NonStrictName, key_type: str = 'ec', **kwargs) -> Key:
        """
        Generate a new key for a specific Identity.

        :param id_name: the Name of Identity.
        :type id_name: :any:`NonStrictName`
        :param key_type: the type of key. Can be one of the following:

            + ``ec``: ECDSA key.
            + ``rsa``: RSA key.

        :param kwargs: keyword arguments.

        :Keyword Arguments:

            + **key_size** (:class:`int`) - key size in bit.
            + **key_id** (Union[:any:`BinaryStr`, :class:`str`]) - a one-Component ID of the Key.
            + **key_id_type** (:class:`str`) - the method to generate the ID if *key_id* is not specified.
              Can be ``random`` or ``sha256``.

        :return: the new Key.
        """
        name = Name.normalize(id_name)
        if name not in self:
            raise KeyError(f'Identity {Name.to_str(id_name)} does not exist')
        identity = self[name]
        key_name, pub_key = self.tpm.generate_key(name, key_type, **kwargs)
        signer = self.tpm.get_signer(key_name)
        cert_name, cert_data = self_sign(key_name, pub_key, signer)
        key_name = Name.to_bytes(key_name)
        cert_name = Name.to_bytes(cert_name)
        self.conn.execute('INSERT INTO keys (identity_id, key_name, key_bits) VALUES (?, ?, ?)',
                          (identity.row_id, key_name, pub_key))
        self.conn.execute('INSERT INTO certificates (key_id, certificate_name, certificate_data)'
                          'VALUES ((SELECT id FROM keys WHERE key_name=?), ?, ?)',
                          (key_name, cert_name, bytes(cert_data)))
        self.conn.commit()

        if not identity.has_default_key():
            identity.set_default_key(key_name)
        return identity[key_name]

    def import_cert(self, key_name: NonStrictName, cert_name: NonStrictName, cert_data: BinaryStr):
        key_name = Name.to_bytes(key_name)
        cert_name = Name.to_bytes(cert_name)
        self.conn.execute('INSERT INTO certificates (key_id, certificate_name, certificate_data)'
                          'VALUES ((SELECT id FROM keys WHERE key_name=?), ?, ?)',
                          (key_name, cert_name, bytes(cert_data)))
        self.conn.commit()
