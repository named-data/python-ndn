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
import sys
import asyncio as aio
from ctypes import cdll, c_void_p, c_ubyte, POINTER, c_int32, c_ulong, c_uint16
from .general import Platform
if sys.platform == 'darwin':
    from ..contrib.cocoapy import cf, CFIndex, CFRange, CFAllocatorRef


class OsxSec(object):
    __instance = None

    def __new__(cls):
        if OsxSec.__instance is None:
            OsxSec.__instance = object.__new__(cls)
        return OsxSec.__instance

    def __init__(self):
        if len(self.__dict__) > 0:
            return
        self.security = cdll.LoadLibrary(
            "/System/Library/Frameworks/Security.framework/Versions/Current/Security")

        def load_func(name, rtype, args):
            func = getattr(self.security, name)
            func.restype = rtype
            func.argtypes = args

        load_func("SecItemCopyMatching", c_int32, [c_void_p, POINTER(c_void_p)])
        load_func("SecItemDelete", c_int32, [c_void_p])
        load_func("SecKeyCreateSignature", c_void_p, [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)])
        load_func("SecKeyIsAlgorithmSupported", c_ubyte, [c_void_p, CFIndex, c_void_p])
        load_func("SecAccessControlCreateWithFlags", c_void_p, [CFAllocatorRef, c_void_p, c_ulong, POINTER(c_void_p)])
        load_func("SecKeyCreateRandomKey", c_void_p, [c_void_p, POINTER(c_void_p)])
        load_func("SecKeyCopyPublicKey", c_void_p, [c_void_p])
        load_func("SecKeyCopyExternalRepresentation", c_void_p, [c_void_p, POINTER(c_void_p)])
        load_func("SecItemAdd", c_int32, [c_void_p, POINTER(c_void_p)])
        load_func("SecItemUpdate", c_int32, [c_void_p, c_void_p])
        load_func("SecAccessCreate", c_int32, [c_void_p, c_void_p, POINTER(c_void_p)])
        load_func("SecACLCreateWithSimpleContents",
                  c_int32,
                  [c_void_p, c_void_p, c_void_p, c_uint16, POINTER(c_void_p)])

        attr_list = ["kSecClass", "kSecClassKey", "kSecAttrLabel", "kSecAttrKeyClass", "kSecAttrKeyClassPrivate",
                     "kSecReturnRef", "kSecReturnAttributes", "kSecValueRef", "kSecAttrKeyType",
                     "kSecAttrKeySizeInBits", "kSecValueRef", "kSecAttrKeyType", "kSecAttrKeySizeInBits",
                     "kSecAttrKeyTypeRSA", "kSecAttrKeyTypeECSECPrimeRandom",
                     "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256",
                     "kSecKeyAlgorithmECDSASignatureDigestX962SHA256", "kSecAttrTokenID",
                     "kSecAttrTokenIDSecureEnclave", "kSecPrivateKeyAttrs", "kSecAttrIsPermanent",
                     "kSecAttrAccessControl", "kSecAttrAccess", "kSecAttrAccessibleAfterFirstUnlock",
                     "kSecAttrApplicationTag"]
        for attr in attr_list:
            setattr(self, attr, c_void_p.in_dll(self.security, attr))
        self.kSecAccessControlPrivateKeyUsage = 1 << 30

        cf.CFRetain.restype = c_void_p
        cf.CFRetain.argtypes = [c_void_p]

        self.kCFBooleanTrue = c_void_p.in_dll(cf, "kCFBooleanTrue")

        self.errSecSuccess = 0
        self.errSecItemNotFound = -25300

    @staticmethod
    def create_data(data: bytes) -> c_void_p:
        return cf.CFDataCreate(None, data, len(data))

    @staticmethod
    def get_data(data_ptr: c_void_p):
        length = cf.CFDataGetLength(data_ptr)
        array = (c_ubyte * length)()
        cf.CFDataGetBytes(data_ptr, CFRange(0, length), array)
        return bytes(array)


class ReleaseGuard:
    def __init__(self):
        self.__dict__['_dict'] = {}

    def __getattr__(self, item):
        return self._dict[item]

    def __setattr__(self, key, value):
        self._dict[key] = value

    def __enter__(self):
        if len(self._dict) > 0:
            raise RuntimeError('Re-enter a ReleaseGuard')
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for v in self._dict.values():
            if v:
                cf.CFRelease(v)
        return False


class Darwin(Platform):
    def client_conf_paths(self):
        return [os.path.expanduser('~/.ndn/client.conf'),
                '/usr/local/etc/ndn/client.conf',
                '/opt/local/etc/ndn/client.conf',
                '/etc/ndn/client.conf']

    def default_transport(self):
        if not os.path.exists('/var/run/nfd/nfd.sock') and os.path.exists('/var/run/nfd.sock'):
            # Try to be compatible to old NFD
            return 'unix:///var/run/nfd.sock'
        return 'unix:///var/run/nfd/nfd.sock'

    def default_pib_scheme(self):
        return 'pib-sqlite3'

    def default_pib_paths(self):
        return [os.path.expanduser(r'~/.ndn')]

    def default_tpm_scheme(self):
        return 'tpm-osxkeychain'

    def default_tpm_paths(self):
        return [os.path.expanduser(r'~/.ndn/ndnsec-key-file')]

    async def open_unix_connection(self, path=None):
        return await aio.open_unix_connection(path)
