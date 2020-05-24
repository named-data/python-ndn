# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 Xinyu Ma
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
import sys
from configparser import ConfigParser
from .security import TpmFile, Keychain, KeychainSqlite3
from .transport.stream_socket import Face, UnixFace, TcpFace
if sys.platform == 'darwin':
    from .security.tpm.tpm_osx_keychain import TpmOsxKeychain


def read_client_conf():
    def get_path():
        path = os.path.expanduser('~/.ndn/client.conf')
        if os.path.exists(path):
            return path
        path = '/usr/local/etc/ndn/client.conf'
        if os.path.exists(path):
            return path
        path = '/opt/local/etc/ndn/client.conf'
        if os.path.exists(path):
            return path
        path = '/etc/ndn/client.conf'
        if os.path.exists(path):
            return path

    def resolve_location(value):
        nonlocal path
        sp = value.split(':')
        if len(sp) == 1:
            schema = value
            loc = ''
        else:
            schema, loc = sp
        if not loc or not os.path.exists(loc):
            if loc and (path is not None):
                loc = os.path.join(os.path.dirname(path), loc)
            if not loc or not os.path.exists(loc):
                loc = '~/.ndn/ndnsec-key-file' if schema == 'tpm-file' else '~/.ndn'
                loc = os.path.expanduser(loc)
        return ':'.join((schema, loc))

    path = get_path()
    ret = {
        'transport': 'unix:///run/nfd.sock' if sys.platform == 'linux' else 'unix:///var/run/nfd.sock',
        'pib': 'pib-sqlite3',
        'tpm': 'tpm-osxkeychain' if sys.platform == 'darwin' else 'tpm-file'
    }
    if path:
        parser = ConfigParser()
        text = '[DEFAULT]\n'
        with open(path) as f:
            text += f.read()
        parser.read_string(text)
        for key in ret.keys():
            try:
                ret[key] = parser['DEFAULT'][key]
            except KeyError:
                pass
    for key in ret.keys():
        try:
            ret[key] = os.environ[f'NDN_CLIENT_{key.upper()}']
        except KeyError:
            pass
    for key in ['pib', 'tpm']:
        ret[key] = resolve_location(ret[key])
    return ret


def default_keychain(pib: str, tpm: str) -> Keychain:
    pib_schema, pib_loc = pib.split(':')
    tpm_schema, tpm_loc = tpm.split(':')
    if tpm_schema == 'tpm-file':
        tpm = TpmFile(tpm_loc)
    elif tpm_schema == 'tpm-osxkeychain':
        tpm = TpmOsxKeychain()
    else:
        raise ValueError(f'Unrecognized tpm schema: {tpm}')
    if pib_schema == 'pib-sqlite3':
        pib = KeychainSqlite3(os.path.join(pib_loc, 'pib.db'), tpm)
    else:
        raise ValueError(f'Unrecognized pib schema: {pib}')
    return pib


def default_face(face: str) -> Face:
    schema, uri = face.split('://')
    if schema == 'unix':
        return UnixFace(uri)
    elif schema == 'tcp' or schema == 'tcp4':
        if uri.find(':') >= 0:
            host, port = uri.split(':')
            port = port
        else:
            host = uri
            port = 6363
        return TcpFace(host, int(port))
    else:
        raise ValueError(f'Unrecognized face: {face}')
