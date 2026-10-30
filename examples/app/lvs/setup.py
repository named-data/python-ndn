# -----------------------------------------------------------------------------
# Copyright (C) 2026 The python-ndn authors
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
import argparse
import os
import shutil
from datetime import UTC, datetime, timedelta

from ndn import encoding as enc
from ndn.app_support.security_v2 import derive_cert
from ndn.security import KeychainSqlite3, TpmFile


def main():
    parser = argparse.ArgumentParser(
        description='Create the keychain used by the LVS examples.',
    )
    parser.add_argument(
        '--force',
        action='store_true',
        help='replace an existing example keychain',
    )
    args = parser.parse_args()

    basedir = os.path.dirname(os.path.abspath(__file__))
    pib_path = os.path.join(basedir, 'pib.db')
    tpm_path = os.path.join(basedir, 'privKeys')
    if os.path.exists(pib_path) or os.path.exists(tpm_path):
        if not args.force:
            parser.error('example keychain exists; use --force to replace it')
        if os.path.exists(pib_path):
            os.unlink(pib_path)
        if os.path.exists(tpm_path):
            shutil.rmtree(tpm_path)

    KeychainSqlite3.initialize(pib_path, 'tpm-file', tpm_path)
    keychain = KeychainSqlite3(pib_path, TpmFile(tpm_path))
    try:
        root = keychain.touch_identity('/lvs-test')
        root_cert = root.default_key().default_cert()
        root_signer = keychain.get_signer({'cert': root_cert.name})

        now = datetime.now(UTC)
        not_after = now + timedelta(days=365)

        admin = keychain.touch_identity('/lvs-test/admin/ndn')
        admin_key = admin.default_key()
        admin_self_cert = admin_key.default_cert()
        admin_cert_name, admin_cert_data = derive_cert(
            admin_key.name,
            enc.Component.from_str('lvs-test'),
            admin_key.key_bits,
            root_signer,
            now,
            int((not_after - now).total_seconds()),
        )
        keychain.import_cert(
            admin_key.name,
            admin_cert_name,
            admin_cert_data,
        )
        admin_key.set_default_cert(admin_cert_name)
        keychain.del_cert(admin_self_cert.name)
        admin_signer = keychain.get_signer({'cert': admin_cert_name})

        author = keychain.touch_identity('/lvs-test/author/xinyu')
        author_key = author.default_key()
        author_self_cert = author_key.default_cert()
        author_cert_name, author_cert_data = derive_cert(
            author_key.name,
            enc.Component.from_str('ndn'),
            author_key.key_bits,
            admin_signer,
            now,
            int((not_after - now).total_seconds()),
        )
        keychain.import_cert(
            author_key.name,
            author_cert_name,
            author_cert_data,
        )
        author_key.set_default_cert(author_cert_name)
        keychain.del_cert(author_self_cert.name)

        print(f'Root:   {enc.Name.to_str(root_cert.name)}')
        print(f'Admin:  {enc.Name.to_str(admin_cert_name)}')
        print(f'Author: {enc.Name.to_str(author_cert_name)}')
    finally:
        keychain.shutdown()


if __name__ == '__main__':
    main()
