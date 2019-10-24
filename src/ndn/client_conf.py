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

    def resolve_loaction(value):
        nonlocal path
        sp = value.split(':')
        if len(sp) == 1:
            schema = value
            loc = ''
        else:
            schema, loc = sp
        if not loc or not os.path.exists(loc):
            if loc:
                loc = os.path.join(os.path.dirname(path), loc)
            if not loc or not os.path.exists(loc):
                loc = '~/.ndn/ndnsec-key-file' if schema == 'tpm-file' else '~/.ndn'
                loc = os.path.expanduser(loc)
        return ':'.join((schema, loc))

    path = get_path()
    ret = {
        'transport': 'unix:///var/run/nfd.sock',
        'pib': 'pib-sqlite3',
        'tpm': 'tpm-osxkeychain' if sys.platform == 'darwin' else 'tpm-file'
    }
    if path:
        parser = ConfigParser()
        text = '[DEFAULT]\n'
        with open(path) as f:
            text += f.read()
        parser.read_string(text)
        for key in ['transport', 'pib', 'tpm']:
            try:
                ret[key] = parser['DEFAULT'][key]
            except KeyError:
                pass
    for key in ['pib', 'tpm']:
        ret[key] = resolve_loaction(ret[key])
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
