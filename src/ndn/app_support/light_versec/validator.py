# -----------------------------------------------------------------------------
# This piece of work is inspired by Pollere' VerSec:
# https://github.com/pollere/DCT
# But this code is implemented independently without using any line of the
# original one, and released under Apache License.
#
# Copyright (C) 2019-2026 The python-ndn authors
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
import logging

from ...app import NDNApp, PktContext, Validator
from ...encoding import BinaryStr, FormalName, Name, SignaturePtrs, parse_data
from ...security.validator.cascade_validator import (
    CascadeChecker,
    MemoryKeyStorage,
    PublicKeyStorage,
)
from ...types import ValidResult
from .checker import Checker


__all__ = ['lvs_validator']


def lvs_validator(
    checker: Checker,
    app: NDNApp,
    trust_anchor: BinaryStr,
    storage: PublicKeyStorage | None = None,
) -> Validator:
    """
    Create a validator that enforces an LVS model and validates certificate chains.

    :param checker: compiled LVS policy checker.
    :param app: application used to fetch certificates.
    :param trust_anchor: wire-encoded trust anchor certificate.
    :param storage: optional cache for fetched public keys.
    :return: validator suitable for :meth:`ndn.app.NDNApp.express`.
    :raises ValueError: if user functions are missing, the trust anchor does
                        not match every LVS trust root, or the trust anchor is
                        not properly self-signed.
    """
    if not checker.validate_user_fns():
        raise ValueError('Missing user functions for LVS validator')

    cert_name, _, _, _ = parse_data(trust_anchor)
    ta_matches = {
        rule_name
        for rule_names, _ in checker.match(cert_name)
        for rule_name in rule_names
    }
    if not ta_matches or not checker.root_of_trust().issubset(ta_matches):
        raise ValueError(
            'Trust anchor does not match all roots of trust of LVS model'
        )

    cascade = CascadeChecker(
        app,
        trust_anchor,
        storage if storage is not None else MemoryKeyStorage(),
    )
    logger = logging.getLogger(__name__)

    async def validate(
        name: FormalName,
        sig_ptrs: SignaturePtrs,
        context: PktContext,
    ) -> ValidResult:
        sig_info = sig_ptrs.signature_info
        if (
            sig_info is None
            or sig_info.key_locator is None
            or sig_info.key_locator.name is None
        ):
            return ValidResult.FAIL

        cert_name = sig_info.key_locator.name
        logger.debug(
            'LVS checking %s <- %s ...',
            Name.to_str(name),
            Name.to_str(cert_name),
        )
        if not checker.check(name, cert_name):
            return ValidResult.FAIL
        return await cascade(name, sig_ptrs, context)

    cascade.next_level = validate
    return validate
