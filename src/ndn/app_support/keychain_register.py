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
import logging
from ..appv2 import NDNApp, ReplyFunc
from .. import security as sec
from .. import encoding as enc
from . import security_v2 as secv2


class KcHandler:
    ident: sec.AbstractIdentity

    def on_int(self, int_name: enc.FormalName, _app_param, reply: ReplyFunc, pkt_ctx):
        logger = logging.getLogger(__name__)
        id_name = self.ident.name
        if not enc.Name.is_prefix(id_name, int_name):
            return
        can_be_prefix = pkt_ctx['int_param'].can_be_prefix
        # can_be_prefix = True if using KEY name, False if using CERT name
        if len(int_name) != len(id_name) + (2 if can_be_prefix else 4):
            logger.warning(f'Invalid key fetching Interest: {enc.Name.to_str(int_name)}')
            return
        try:
            key_name = int_name[:len(id_name)+2]
            key = self.ident[key_name]
            cert = None
            if can_be_prefix:
                # fetch KEY
                for _, cur_cert in key.items():
                    cert = cur_cert
                    break
            else:
                cert = key[int_name]
            if cert is not None:
                logger.info(f'KeychainRegister replied with: {enc.Name.to_str(cert.name)}')
                reply(cert.data)
            else:
                logger.warning(f'No certificate for key: {enc.Name.to_str(int_name)}')
        except KeyError:
            logger.warning(f'Fetching not existing key/cert: {enc.Name.to_str(int_name)}')

    def __init__(self, ident: sec.AbstractIdentity):
        self.ident = ident


def attach_keychain_register(keychain: sec.Keychain, app: NDNApp):
    for name, ident in keychain.items():
        reg_name = name + [secv2.KEY_COMPONENT]
        handler = KcHandler(ident)
        app.route(reg_name)(handler.on_int)
