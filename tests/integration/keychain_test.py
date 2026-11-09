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
import os
from tempfile import TemporaryDirectory
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import ECC
from Cryptodome.Signature import DSS
from ndn.encoding import make_data, MetaInfo, parse_data, Name
from ndn.security import KeychainDigest, KeychainSqlite3, TpmFile


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
            self.verify_signature_time_opt_out()

            self.keychain.del_identity('test')
            assert len(self.keychain) == 0
            self.keychain.shutdown()

    def prepare_db(self, base_dir):
        self.pib_file = os.path.join(base_dir, 'pib.db')
        self.tpm_dir = os.path.join(base_dir, 'ndnsec-key-file')
        KeychainSqlite3.initialize(self.pib_file, 'tpm-file', self.tpm_dir)

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
        return sig_ptrs.signature_info.key_locator.name

    def verify_data(self):
        signer = self.keychain.get_signer({})
        data = make_data('/test/data', MetaInfo(), b'content', signer=signer)
        key_locator_name = self.verify(data)
        assert (Name.normalize(key_locator_name) ==
                Name.normalize(self.keychain.default_identity().default_key().default_cert().name))

    def verify_cert(self):
        key_locator_name = self.verify(self.cert)
        assert key_locator_name == self.keychain.default_identity().default_key().name

    def verify_signature_time_opt_out(self):
        # Default signer (already cached by verify_data) writes a signature time
        default_signer = self.keychain.get_signer({})
        assert default_signer.with_signature_time is True
        data = make_data('/test/data', MetaInfo(), b'content', signer=default_signer)
        _, _, _, sig_ptrs = parse_data(data)
        assert sig_ptrs.signature_info.signature_time is not None

        # Opting out must not return the cached default signer
        opt_out_signer = self.keychain.get_signer({'with_signature_time': False})
        assert opt_out_signer is not default_signer
        assert opt_out_signer.with_signature_time is False
        data = make_data('/test/data', MetaInfo(), b'content', signer=opt_out_signer)
        _, _, _, sig_ptrs = parse_data(data)
        assert sig_ptrs.signature_info.signature_time is None

        # Both variants remain distinctly cached
        assert self.keychain.get_signer({}) is default_signer
        assert self.keychain.get_signer({'with_signature_time': False}) is opt_out_signer

        # The digest_sha256 branch also honors the flag
        digest_signer = self.keychain.get_signer({'digest_sha256': True, 'with_signature_time': False})
        assert digest_signer.with_signature_time is False


def test_keychain_digest_signature_time_opt_out():
    keychain = KeychainDigest()
    assert keychain.get_signer({}).with_signature_time is True
    assert keychain.get_signer({'with_signature_time': False}).with_signature_time is False
    data = make_data('/test/data', MetaInfo(), b'content',
                     signer=keychain.get_signer({'with_signature_time': False}))
    _, _, _, sig_ptrs = parse_data(data)
    assert sig_ptrs.signature_info.signature_time is None
