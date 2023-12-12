# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
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
import aenum
import socket
import asyncio as aio
import ctypes as c
from .general import Platform


class SockaddrUn(c.Structure):
    _fields_ = [("sun_family", c.c_ushort), ("sun_path", c.c_char * 108)]


aenum.extend_enum(socket.AddressFamily, "AF_UNIX", 1)
AF_UNIX = socket.AddressFamily(1)
NULL = 0


class Cng:
    __instance = None

    STATUS_UNSUCCESSFUL = c.c_long(0xC0000001).value  # -0x3FFFFFFF
    NTE_BAD_KEYSET = c.c_long(0x80090016).value
    NCRYPT_OVERWRITE_KEY_FLAG = c.c_long(0x00000080)
    BCRYPT_SHA256_ALGORITHM = c.c_wchar_p('SHA256')
    BCRYPT_ECDSA_P256_ALGORITHM = c.c_wchar_p('ECDSA_P256')
    BCRYPT_ECDSA_P384_ALGORITHM = c.c_wchar_p('ECDSA_P384')
    BCRYPT_ECDSA_P521_ALGORITHM = c.c_wchar_p('ECDSA_P521')
    NCRYPT_ECDSA_P256_ALGORITHM = BCRYPT_ECDSA_P256_ALGORITHM
    NCRYPT_ECDSA_P384_ALGORITHM = BCRYPT_ECDSA_P384_ALGORITHM
    NCRYPT_ECDSA_P521_ALGORITHM = BCRYPT_ECDSA_P521_ALGORITHM
    BCRYPT_OBJECT_LENGTH = c.c_wchar_p('ObjectLength')
    BCRYPT_HASH_LENGTH = c.c_wchar_p('HashDigestLength')
    MS_PLATFORM_KEY_STORAGE_PROVIDER = c.c_wchar_p(
        'Microsoft Platform Crypto Provider')
    MS_KEY_STORAGE_PROVIDER = c.c_wchar_p(
        'Microsoft Software Key Storage Provider')
    BCRYPT_ECCPUBLIC_BLOB = c.c_wchar_p('ECCPUBLICBLOB')
    BCRYPT_ECCPRIVATE_BLOB = c.c_wchar_p('ECCPRIVATEBLOB')

    class BcryptEcckeyBlob(c.Structure):
        _fields_ = [("dw_magic", c.c_ulong), ("cb_key", c.c_ulong)]

    @staticmethod
    def nt_success(status):
        return status >= 0

    def __new__(cls):
        if Cng.__instance is None:
            Cng.__instance = object.__new__(cls)
        return Cng.__instance

    def __init__(self):
        if len(self.__dict__) > 0:
            return
        self.bcrypt = c.windll.bcrypt
        self.ncrypt = c.windll.ncrypt


class Win32(Platform):
    def client_conf_paths(self):
        return [os.path.expandvars(r'%LOCALAPPDATA%\ndn\client.conf'),
                os.path.expandvars(r'%USERPROFILE%\ndn\client.conf'),
                os.path.expandvars(r'%ALLUSERSPROFILE%\ndn\client.conf')]

    def default_transport(self):
        # Note: %TEMP% won't be redirected even when the executable is a MSIX/MicrosoftStore app
        oldPath = os.path.expandvars(r'%TEMP%\nfd.sock')
        newPath = os.path.expandvars(r'%TEMP%\nfd\nfd.sock')
        if not os.path.exists(newPath) and os.path.exists(oldPath):
            # Try to be compatible to old NFD
            return 'unix://' + oldPath
        return 'unix://' + newPath

    def default_pib_scheme(self):
        return 'pib-sqlite3'

    def default_pib_paths(self):
        return [os.path.expandvars(r'%LOCALAPPDATA%\ndn'),
                os.path.expandvars(r'%USERPROFILE%\ndn')]

    def default_tpm_scheme(self):
        return 'tpm-cng'

    def default_tpm_paths(self):
        return [os.path.expandvars(r'%LOCALAPPDATA%\ndn\ndnsec-key-file'),
                os.path.expandvars(r'%USERPROFILE%\ndn\ndnsec-key-file')]

    @staticmethod
    def _iocp_connect(proactor, conn, address):
        # _overlapped.WSAConnect(conn.fileno(), address)
        addr = SockaddrUn(AF_UNIX.value, address.encode() + b"\0")
        winsock = c.windll.ws2_32
        winsock.connect(conn.fileno(), addr, 110)

        fut = proactor._loop.create_future()
        fut.set_result(None)
        return fut

    @staticmethod
    async def _create_unix_connection(
            loop, protocol_factory, path=None, *,
            ssl=None, sock=None,
            server_hostname=None,
            ssl_handshake_timeout=None):
        assert server_hostname is None or isinstance(server_hostname, str)
        if ssl:
            if server_hostname is None:
                raise ValueError(
                    'you have to pass server_hostname when using ssl')
        else:
            if server_hostname is not None:
                raise ValueError('server_hostname is only meaningful with ssl')
            if ssl_handshake_timeout is not None:
                raise ValueError(
                    'ssl_handshake_timeout is only meaningful with ssl')

        if path is not None:
            if sock is not None:
                raise ValueError(
                    'path and sock can not be specified at the same time')

            path = os.fspath(path)
            sock = socket.socket(AF_UNIX, socket.SOCK_STREAM, 0)
            try:
                sock.setblocking(False)
                # await loop.sock_connect(sock, path)
                await Win32._iocp_connect(loop._proactor, sock, path)
            except OSError:
                sock.close()
                raise

        else:
            if sock is None:
                raise ValueError('no path and sock were specified')
            if sock.family != AF_UNIX or sock.type != socket.SOCK_STREAM:
                raise ValueError(
                    f'A UNIX Domain Stream Socket was expected, got {sock!r}')
            sock.setblocking(False)

        transport, protocol = await loop._create_connection_transport(
            sock, protocol_factory, ssl, server_hostname,
            ssl_handshake_timeout=ssl_handshake_timeout)
        return transport, protocol

    async def open_unix_connection(self, path=None):
        """
        Similar to `open_connection` but works with UNIX Domain Sockets.
        """
        loop = aio.events.get_running_loop()
        reader = aio.StreamReader(limit=2 ** 16, loop=loop)
        protocol = aio.StreamReaderProtocol(reader, loop=loop)
        transport, _ = await Win32._create_unix_connection(loop, lambda: protocol, path)
        writer = aio.StreamWriter(transport, protocol, reader, loop)
        return reader, writer


class ReleaseGuard:
    def __init__(self):
        self.__dict__['_list'] = []

    def __getattr__(self, idx):
        return self._list[idx]

    def __setattr__(self, idx, value):
        self._list[idx] = value

    def __iadd__(self, defer):
        self._list.append(defer)
        return self

    def __enter__(self):
        if len(self._list) > 0:
            raise RuntimeError('Re-enter a ReleaseGuard')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._list.reverse()
        for f in self._list:
            if f:
                f()
        return False
