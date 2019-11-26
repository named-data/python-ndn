# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
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
import os
import sqlite3
from tempfile import TemporaryDirectory
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ndn.encoding import make_data, MetaInfo, parse_data, Name
from ndn.security import KeychainSqlite3, TpmFile


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


class TestKeychainSqlite3:
    tpm_dir: str
    pib_file: str
    keychain: KeychainSqlite3
    tpm: TpmFile
    pub_key: bytes
    cert: bytes

    def test_main(self):
        with TemporaryDirectory() as tmpdirname:
            self.prepare_db(tmpdirname)
            self.tpm = TpmFile(self.tpm_dir)
            self.keychain = KeychainSqlite3(self.pib_file, self.tpm)

            self.create_key()
            self.verify_data()
            self.verify_cert()

            self.keychain.del_identity('test')
            assert len(self.keychain) == 0

    def prepare_db(self, base_dir):
        self.pib_file = os.path.join(base_dir, 'pib.db')
        self.tpm_dir = os.path.join(base_dir, 'ndnsec-key-file')
        os.makedirs(self.tpm_dir)

        conn = sqlite3.connect(self.pib_file)
        conn.executescript(INITIALIZE_SQL)
        conn.execute('INSERT INTO tpmInfo (tpm_locator) VALUES (?)', (self.pib_file.encode(),))
        conn.commit()
        conn.close()

    def create_key(self):
        self.keychain.touch_identity('test')
        ident = self.keychain.default_identity()
        assert ident.name == Name.from_str('test')
        self.pub_key = ident.default_key().key_bits
        self.cert = ident.default_key().default_cert().data

    def verify(self, pkt):
        _, _, _, sig_ptrs = parse_data(pkt)
        pub_key = ECC.import_key(self.pub_key)
        verifier = DSS.new(pub_key, 'fips-186-3', 'der')
        h = SHA256.new()
        for content in sig_ptrs.signature_covered_part:
            h.update(content)
        verifier.verify(h, bytes(sig_ptrs.signature_value_buf))

    def verify_data(self):
        signer = self.keychain.get_signer({})
        data = make_data('/test/data', MetaInfo(), b'content', signer=signer)
        self.verify(data)

    def verify_cert(self):
        self.verify(self.cert)
