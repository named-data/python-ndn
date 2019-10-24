# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# From PyNDN2: https://github.com/named-data/PyNDN2/blob/master/python/pyndn/security/tpm/tpm_back_end_osx.py
# Original Author: Jeff Thompson <jefft0@remap.ucla.edu>
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
import sys
from ctypes import cdll, c_void_p, c_ubyte, POINTER
if sys.platform == 'darwin':
    from ..cocoapy import cf, CFIndex, CFRange


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

        self.security.SecItemCopyMatching.restype = c_void_p
        self.security.SecItemCopyMatching.argtypes = [c_void_p, POINTER(c_void_p)]

        self.security.SecKeyCreateSignature.restype = c_void_p
        self.security.SecKeyCreateSignature.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]

        self.security.SecKeyIsAlgorithmSupported.restype = c_ubyte
        self.security.SecKeyIsAlgorithmSupported.argtypes = [c_void_p, CFIndex, c_void_p]

        self.kSecClass = c_void_p.in_dll(self.security, "kSecClass")
        self.kSecClassKey = c_void_p.in_dll(self.security, "kSecClassKey")
        self.kSecAttrLabel = c_void_p.in_dll(self.security, "kSecAttrLabel")
        self.kSecAttrKeyClass = c_void_p.in_dll(self.security, "kSecAttrKeyClass")
        self.kSecAttrKeyClassPrivate = c_void_p.in_dll(self.security, "kSecAttrKeyClassPrivate")
        self.kSecReturnRef = c_void_p.in_dll(self.security, "kSecReturnRef")
        self.kSecReturnAttributes = c_void_p.in_dll(self.security, "kSecReturnAttributes")
        self.kSecValueRef = c_void_p.in_dll(self.security, "kSecValueRef")
        self.kSecAttrKeyType = c_void_p.in_dll(self.security, "kSecAttrKeyType")
        self.kSecAttrKeySizeInBits = c_void_p.in_dll(self.security, "kSecAttrKeySizeInBits")
        self.kSecAttrKeyTypeRSA = c_void_p.in_dll(self.security, "kSecAttrKeyTypeRSA")
        self.kSecAttrKeyTypeECSECPrimeRandom = c_void_p.in_dll(self.security, "kSecAttrKeyTypeECSECPrimeRandom")
        self.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256 = c_void_p.in_dll(
            self.security, "kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256")
        self.kSecKeyAlgorithmECDSASignatureDigestX962SHA256 = c_void_p.in_dll(
            self.security, "kSecKeyAlgorithmECDSASignatureDigestX962SHA256")

        cf.CFRetain.restype = c_void_p
        cf.CFRetain.argtypes = [c_void_p]

        self.kCFBooleanTrue = c_void_p.in_dll(cf, "kCFBooleanTrue")

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
