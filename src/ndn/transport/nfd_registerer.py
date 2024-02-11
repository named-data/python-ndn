# -----------------------------------------------------------------------------
# Copyright (C) 2019-2023 The python-ndn authors
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
import logging
from .. import encoding as enc
from .. import security as sec
from .. import types
from .. import utils
from ..app_support import nfd_mgmt
from .prefix_registerer import PrefixRegisterer


async def pass_all(_name, _sig, _context):
    return types.ValidResult.PASS


class NfdRegister(PrefixRegisterer):
    _prefix_register_semaphore: aio.Semaphore = None
    _last_command_timestamp: int = 0

    def __init__(self):
        super().__init__()
        self._prefix_register_semaphore = aio.Semaphore(1)

    async def register(self, name: enc.NonStrictName) -> bool:
        # Fix the issue that NFD only allows one packet signed by a specific key for a timestamp number
        async with self._prefix_register_semaphore:
            for _ in range(10):
                now = utils.timestamp()
                if now > self._last_command_timestamp:
                    self._last_command_timestamp = now
                    break
                await aio.sleep(0.001)
            try:
                _, reply, _ = await self.app.express(
                    name=nfd_mgmt.make_command_v2('rib', 'register', self.app.face, name=name),
                    app_param=b'', signer=sec.DigestSha256Signer(for_interest=True),
                    validator=pass_all,
                    lifetime=1000)
                ret = nfd_mgmt.parse_response(reply)
                if ret['status_code'] != 200:
                    logging.getLogger(__name__).error(f'Registration for {enc.Name.to_str(name)} failed: '
                                                      f'{ret["status_code"]} {ret["status_text"]}')
                    return False
                else:
                    logging.getLogger(__name__).debug(f'Registration for {enc.Name.to_str(name)} succeeded: '
                                                      f'{ret["status_code"]} {ret["status_text"]}')
                    return True
            except (types.InterestNack, types.InterestTimeout, types.InterestCanceled, types.ValidationFailure) as e:
                logging.getLogger(__name__).error(
                    f'Registration for {enc.Name.to_str(name)} failed: {e.__class__.__name__}')
                return False

    async def unregister(self, name: enc.NonStrictName) -> bool:
        # Fix the issue that NFD only allows one packet signed by a specific key for a timestamp number
        async with self._prefix_register_semaphore:
            for _ in range(10):
                now = utils.timestamp()
                if now > self._last_command_timestamp:
                    self._last_command_timestamp = now
                    break
                await aio.sleep(0.001)
            try:
                await self.app.express(
                    nfd_mgmt.make_command_v2('rib', 'unregister', self.app.face, name=name),
                    app_param=b'', signer=sec.DigestSha256Signer(for_interest=True),
                    validator=pass_all, lifetime=1000)
                return True
            except (types.InterestNack, types.InterestTimeout, types.InterestCanceled, types.ValidationFailure):
                return False
