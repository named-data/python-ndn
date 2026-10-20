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
import asyncio as aio
import os
from datetime import UTC, datetime
from hashlib import sha256
from tempfile import TemporaryDirectory
from unittest.mock import patch

import pytest

from ndn import app as ndn_app, encoding as enc, types, utils
from ndn.app_support.light_versec import (
    Checker,
    compile_lvs,
    lvs_validator,
)
from ndn.app_support.security_v2 import derive_cert
from ndn.security import (
    CascadeChecker,
    HmacSha256Signer,
    KeychainSqlite3,
    MemoryKeyStorage,
    TpmFile,
)
from ndn.transport.dummy_face import DummyFace


LVS_TEXT = r'''
#KEY: "KEY"/_/_/_
#article: "lvs-test"/"article"/author/post <= #author
#author: "lvs-test"/"author"/author/#KEY <= #root
#root: "lvs-test"/#KEY
'''


class FakeApp:
    def __init__(self, packets: list[enc.BinaryStr]):
        self.packets = {
            enc.Name.to_bytes(enc.parse_data(packet)[0]): packet
            for packet in packets
        }
        self.expressed: list[enc.FormalName] = []

    async def express(self, name, validator, **kwargs):
        name = enc.Name.normalize(name)
        self.expressed.append(name)
        lookup_name = name
        implicit_digest = None
        if (
            name
            and enc.Component.get_type(name[-1])
            == enc.Component.TYPE_IMPLICIT_SHA256
        ):
            lookup_name = name[:-1]
            implicit_digest = bytes(enc.Component.get_value(name[-1]))
        try:
            packet = self.packets[enc.Name.to_bytes(lookup_name)]
        except KeyError:
            raise types.InterestTimeout()
        if (
            implicit_digest is not None
            and sha256(bytes(packet)).digest() != implicit_digest
        ):
            raise types.InterestTimeout()

        data_name, meta_info, content, sig_ptrs = enc.parse_data(packet)
        context = {
            'meta_info': meta_info,
            'sig_ptrs': sig_ptrs,
            'raw_packet': packet,
            'deadline': utils.timestamp() + kwargs.get('lifetime', 4000),
        }
        result = await validator(data_name, sig_ptrs, context)
        if result not in (types.ValidResult.PASS, types.ValidResult.ALLOW_BYPASS):
            raise types.ValidationFailure(
                data_name,
                meta_info,
                content,
                sig_ptrs,
                result,
            )
        return data_name, content, context


def make_chain(
    base_dir: str,
    cert_start: datetime | None = None,
    cert_lifetime: int = 3600,
):
    pib_file = os.path.join(base_dir, 'pib.db')
    tpm_dir = os.path.join(base_dir, 'privKeys')
    KeychainSqlite3.initialize(pib_file, 'tpm-file', tpm_dir)
    keychain = KeychainSqlite3(pib_file, TpmFile(tpm_dir))

    root = keychain.touch_identity('/lvs-test')
    root_cert = root.default_key().default_cert()
    root_signer = keychain.get_signer({'cert': root_cert.name})

    author = keychain.touch_identity('/lvs-test/author/alice')
    author_key = author.default_key()
    author_cert_name, author_cert_data = derive_cert(
        author_key.name,
        enc.Component.from_str('root'),
        author_key.key_bits,
        root_signer,
        cert_start if cert_start is not None else datetime.now(UTC),
        cert_lifetime,
    )
    keychain.import_cert(
        author_key.name,
        author_cert_name,
        author_cert_data,
    )
    author_signer = keychain.get_signer({'cert': author_cert_name})

    data_packet = enc.make_data(
        '/lvs-test/article/alice/post',
        enc.MetaInfo(),
        b'content',
        author_signer,
    )
    return keychain, root_cert, author_cert_data, data_packet


def make_certificate_with_truncated_validity(
    certificate: enc.BinaryStr,
    signer: enc.Signer,
) -> bytearray:
    wire = bytearray(certificate)
    not_after_header = b'\xfd\x00\xff\x0f'
    not_after_pos = wire.index(not_after_header)
    not_after_size = len(not_after_header) + 15
    wire[not_after_pos:not_after_pos + not_after_size] = (
        b'\x02\x10' + bytes(16) + b'\xfd'
    )

    _, _, _, sig_ptrs = enc.parse_data(wire)
    covered = b''.join(bytes(block) for block in sig_ptrs.signature_covered_part)
    signature_buf = bytearray(signer.get_signature_value_size())
    signature_size = signer.write_signature_value(
        signature_buf,
        sig_ptrs.signature_covered_part,
    )

    signature_tlv = bytearray(
        enc.get_tl_num_size(enc.TypeNumber.SIGNATURE_VALUE)
        + enc.get_tl_num_size(signature_size)
        + signature_size
    )
    offset = enc.write_tl_num(
        enc.TypeNumber.SIGNATURE_VALUE,
        signature_tlv,
        0,
    )
    offset += enc.write_tl_num(signature_size, signature_tlv, offset)
    signature_tlv[offset:] = signature_buf[:signature_size]

    value = covered + signature_tlv
    ret = bytearray(
        enc.get_tl_num_size(enc.TypeNumber.DATA)
        + enc.get_tl_num_size(len(value))
        + len(value)
    )
    offset = enc.write_tl_num(enc.TypeNumber.DATA, ret, 0)
    offset += enc.write_tl_num(len(value), ret, offset)
    ret[offset:] = value
    return ret


class TestLvsValidator:
    @staticmethod
    def test_certificate_chain_and_cache():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, author_cert, data_packet = make_chain(base_dir)
                try:
                    fake_app = FakeApp([author_cert])
                    checker = Checker(compile_lvs(LVS_TEXT), {})
                    validator = lvs_validator(
                        checker,
                        fake_app,
                        root_cert.data,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(data_packet)
                    context = {'deadline': utils.timestamp() + 4000}

                    assert (
                        await validator(name, sig_ptrs, context)
                        is types.ValidResult.PASS
                    )
                    assert len(fake_app.expressed) == 1

                    assert (
                        await validator(name, sig_ptrs, context)
                        is types.ValidResult.PASS
                    )
                    assert len(fake_app.expressed) == 1
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_policy_and_signature_failures():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, author_cert, data_packet = make_chain(base_dir)
                try:
                    fake_app = FakeApp([author_cert])
                    checker = Checker(compile_lvs(LVS_TEXT), {})
                    validator = lvs_validator(
                        checker,
                        fake_app,
                        root_cert.data,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(data_packet)
                    context = {'deadline': utils.timestamp() + 4000}

                    assert (
                        await validator(
                            enc.Name.from_str('/lvs-test/article/bob/post'),
                            sig_ptrs,
                            context,
                        )
                        is types.ValidResult.FAIL
                    )
                    assert not fake_app.expressed

                    sig_ptrs.signature_value_buf = bytes(
                        len(sig_ptrs.signature_value_buf)
                    )
                    assert (
                        await validator(name, sig_ptrs, context)
                        is types.ValidResult.FAIL
                    )
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_rejects_invalid_trust_anchor():
        with TemporaryDirectory() as base_dir:
            keychain, root_cert, _, _ = make_chain(base_dir)
            try:
                trust_anchor = bytearray(root_cert.data)
                trust_anchor[-1] ^= 0x01
                checker = Checker(compile_lvs(LVS_TEXT), {})
                with pytest.raises(
                    ValueError,
                    match='Trust anchor is not properly self-signed',
                ):
                    lvs_validator(checker, FakeApp([]), trust_anchor)
            finally:
                keychain.shutdown()

    @staticmethod
    def test_rejects_expired_certificate():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, author_cert, data_packet = make_chain(
                    base_dir,
                    cert_start=datetime(2000, 1, 1, tzinfo=UTC),
                )
                try:
                    validator = lvs_validator(
                        Checker(compile_lvs(LVS_TEXT), {}),
                        FakeApp([author_cert]),
                        root_cert.data,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(data_packet)
                    assert (
                        await validator(
                            name,
                            sig_ptrs,
                            {'deadline': utils.timestamp() + 4000},
                        )
                        is types.ValidResult.FAIL
                    )
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_rejects_truncated_validity_tlv_header():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, author_cert, data_packet = make_chain(
                    base_dir
                )
                try:
                    root_signer = keychain.get_signer(
                        {'cert': root_cert.name}
                    )
                    malformed_cert = make_certificate_with_truncated_validity(
                        author_cert,
                        root_signer,
                    )
                    _, root_key, _ = CascadeChecker._parse_certificate(
                        root_cert.data
                    )
                    _, _, _, cert_sig_ptrs = enc.parse_data(malformed_cert)
                    assert CascadeChecker._verify_sig(
                        root_key,
                        cert_sig_ptrs,
                    )

                    validator = CascadeChecker(
                        FakeApp([malformed_cert]),
                        root_cert.data,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(data_packet)
                    assert (
                        await validator(
                            name,
                            sig_ptrs,
                            {'deadline': utils.timestamp() + 4000},
                        )
                        is types.ValidResult.FAIL
                    )
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_preserves_recursive_timeout():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, _, data_packet = make_chain(base_dir)
                try:
                    class TimeoutApp:
                        @staticmethod
                        async def express(_name, validator, **_kwargs):
                            raise types.ValidationFailure(
                                [],
                                enc.MetaInfo(),
                                None,
                                enc.SignaturePtrs(),
                                types.ValidResult.TIMEOUT,
                            )

                    validator = lvs_validator(
                        Checker(compile_lvs(LVS_TEXT), {}),
                        TimeoutApp(),
                        root_cert.data,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(data_packet)
                    assert (
                        await validator(
                            name,
                            sig_ptrs,
                            {'deadline': utils.timestamp() + 4000},
                        )
                        is types.ValidResult.TIMEOUT
                    )
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_memory_cache_is_bounded_and_expiry_aware():
        storage = MemoryKeyStorage(max_entries=2)
        storage.save('/cert/1', b'one')
        storage.save('/cert/2', b'two')
        storage.save('/cert/3', b'three')
        assert storage.load(enc.Name.from_str('/cert/1')) is None
        assert storage.load(enc.Name.from_str('/cert/2')) == b'two'

        storage.save_with_expiration(
            enc.Name.from_str('/cert/4'),
            b'four',
            utils.timestamp() - 1,
        )
        assert storage.load(enc.Name.from_str('/cert/4')) is None

    @staticmethod
    def test_cascade_rejects_hmac():
        secret = b'not a public key'
        packet = enc.make_data(
            '/data',
            enc.MetaInfo(),
            b'content',
            HmacSha256Signer('/key', secret),
        )
        _, _, _, sig_ptrs = enc.parse_data(packet)
        assert not CascadeChecker._verify_sig(secret, sig_ptrs)

    @staticmethod
    def test_implicit_digest_certificate_locator():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, author_cert, _ = make_chain(base_dir)
                try:
                    author_cert_name = enc.parse_data(author_cert)[0]
                    implicit_digest = enc.Component.from_bytes(
                        sha256(bytes(author_cert)).digest(),
                        enc.Component.TYPE_IMPLICIT_SHA256,
                    )
                    locator_name = author_cert_name + [implicit_digest]
                    author_key = keychain[
                        '/lvs-test/author/alice'
                    ].default_key()
                    signer = keychain.tpm.get_signer(
                        author_key.name,
                        locator_name,
                    )
                    packet = enc.make_data(
                        '/lvs-test/article/alice/post',
                        enc.MetaInfo(),
                        b'content',
                        signer,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(packet)
                    validator = lvs_validator(
                        Checker(compile_lvs(LVS_TEXT), {}),
                        FakeApp([author_cert]),
                        root_cert.data,
                    )
                    assert (
                        await validator(
                            name,
                            sig_ptrs,
                            {'deadline': utils.timestamp() + 4000},
                        )
                        is types.ValidResult.PASS
                    )
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_rechecks_trust_anchor_expiration():
        with TemporaryDirectory() as base_dir:
            keychain, root_cert, _, _ = make_chain(base_dir)
            try:
                cascade = CascadeChecker(FakeApp([]), root_cert.data)
                packet = enc.make_data(
                    '/data',
                    enc.MetaInfo(),
                    b'content',
                    keychain.get_signer({'cert': root_cert.name}),
                )
                name, _, _, sig_ptrs = enc.parse_data(packet)
                with patch(
                    'ndn.security.validator.cascade_validator.timestamp',
                    return_value=cascade.anchor_expires_at + 1,
                ):
                    assert (
                        aio.run(
                            cascade(
                                name,
                                sig_ptrs,
                                {'deadline': cascade.anchor_expires_at + 1000},
                            )
                        )
                        is types.ValidResult.FAIL
                    )
            finally:
                keychain.shutdown()

    @staticmethod
    def test_rejects_cyclic_certificate_chain():
        async def scenario():
            with TemporaryDirectory() as base_dir:
                keychain, root_cert, _, _ = make_chain(base_dir)
                try:
                    identity_a = keychain.touch_identity('/cycle/a')
                    identity_b = keychain.touch_identity('/cycle/b')
                    key_a = identity_a.default_key()
                    key_b = identity_b.default_key()
                    version = utils.timestamp()
                    issuer = enc.Component.from_str('cycle')
                    cert_a_name = key_a.name + [
                        issuer,
                        enc.Component.from_version(version),
                    ]
                    cert_b_name = key_b.name + [
                        issuer,
                        enc.Component.from_version(version),
                    ]
                    signer_a = keychain.tpm.get_signer(
                        key_a.name,
                        cert_a_name,
                    )
                    signer_b = keychain.tpm.get_signer(
                        key_b.name,
                        cert_b_name,
                    )
                    with patch(
                        'ndn.app_support.security_v2.timestamp',
                        return_value=version,
                    ):
                        actual_a_name, cert_a = derive_cert(
                            key_a.name,
                            issuer,
                            key_a.key_bits,
                            signer_b,
                            datetime.now(UTC),
                            3600,
                        )
                        actual_b_name, cert_b = derive_cert(
                            key_b.name,
                            issuer,
                            key_b.key_bits,
                            signer_a,
                            datetime.now(UTC),
                            3600,
                        )
                    assert actual_a_name == cert_a_name
                    assert actual_b_name == cert_b_name

                    packet = enc.make_data(
                        '/data',
                        enc.MetaInfo(),
                        b'content',
                        signer_a,
                    )
                    name, _, _, sig_ptrs = enc.parse_data(packet)
                    fake_app = FakeApp([cert_a, cert_b])
                    cascade = CascadeChecker(
                        fake_app,
                        root_cert.data,
                        max_depth=4,
                    )
                    assert (
                        await cascade(
                            name,
                            sig_ptrs,
                            {'deadline': utils.timestamp() + 4000},
                        )
                        is types.ValidResult.FAIL
                    )
                    assert len(fake_app.expressed) == 2
                finally:
                    keychain.shutdown()

        aio.run(scenario())

    @staticmethod
    def test_ndn_app_certificate_fetch():
        with TemporaryDirectory() as base_dir:
            keychain, root_cert, author_cert, data_packet = make_chain(base_dir)
            try:
                async def face_proc(face):
                    await face.ignore_output(1)
                    await face.input_packet(data_packet)
                    await face.ignore_output(1)
                    await face.input_packet(author_cert)

                face = DummyFace(face_proc)
                app = ndn_app.NDNApp(face)
                face.app = app
                checker = Checker(compile_lvs(LVS_TEXT), {})
                validator = lvs_validator(checker, app, root_cert.data)

                async def after_start():
                    name, content, _ = await app.express(
                        '/lvs-test/article/alice/post',
                        validator=validator,
                        nonce=None,
                        lifetime=1000,
                    )
                    assert name == enc.Name.from_str(
                        '/lvs-test/article/alice/post'
                    )
                    assert content == b'content'

                aio.run(app.main_loop(after_start()))
            finally:
                keychain.shutdown()
