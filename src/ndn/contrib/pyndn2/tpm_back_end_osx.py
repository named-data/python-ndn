# -*- Mode:python; c-file-style:"gnu"; indent-tabs-mode:nil -*- */
#
# This file is modified from the file with the same name in PyNDN2
# https://github.com/named-data/PyNDN2/blob/master/python/pyndn/security/tpm/tpm_back_end_osx.py
#
# Copyright (C) 2017-2019 Regents of the University of California.
# Author: Jeff Thompson <jefft0@remap.ucla.edu>
# Author: From ndn-cxx security https://github.com/named-data/ndn-cxx/blob/master/ndn-cxx/security/tpm/back-end-osx.cpp
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
# A copy of the GNU Lesser General Public License is in the file COPYING.

import sys
from ctypes import *
if sys.platform == 'darwin':
    from ..cocoapy import cf


class SecKeychainAttribute(Structure):
    _fields_ = [("tag", c_uint32),
                ("length", c_uint32),
                ("data", c_char_p)]


class SecKeychainAttributeList(Structure):
    _fields_ = [("count", c_int),
                ("attr", POINTER(SecKeychainAttribute))]


class Osx(object):
    _instance = None

    def __init__(self):
        self._kCFBooleanTrue = c_void_p.in_dll(cf, "kCFBooleanTrue")

        self._security = cdll.LoadLibrary(
          "/System/Library/Frameworks/Security.framework/Versions/Current/Security")
        self._security.SecItemCopyMatching.restype = c_void_p
        self._security.SecItemCopyMatching.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecSignTransformCreate.restype = c_void_p
        self._security.SecSignTransformCreate.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecDecryptTransformCreate.restype = c_void_p
        self._security.SecDecryptTransformCreate.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecTransformSetAttribute.restype = c_void_p
        self._security.SecTransformSetAttribute.argtypes = [c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]

        self._security.SecTransformExecute.restype = c_void_p
        self._security.SecTransformExecute.argtypes = [c_void_p, POINTER(c_void_p)]

        self._security.SecItemExport.restype = c_void_p
        self._security.SecItemExport.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, POINTER(c_void_p)]

        self._security.SecKeychainSetUserInteractionAllowed.restype = c_void_p
        self._security.SecKeychainSetUserInteractionAllowed.argtypes = [c_void_p]

        self._security.SecKeychainItemModifyAttributesAndData.restype = c_void_p
        self._security.SecKeychainItemModifyAttributesAndData.argtypes = [
          c_void_p, POINTER(SecKeychainAttributeList), c_uint32, c_void_p]

        self._kSecClass = c_void_p.in_dll(self._security, "kSecClass")
        self._kSecClassKey = c_void_p.in_dll(self._security, "kSecClassKey")
        self._kSecAttrKeyType = c_void_p.in_dll(self._security, "kSecAttrKeyType")
        self._kSecAttrKeySizeInBits = c_void_p.in_dll(self._security, "kSecAttrKeySizeInBits")
        self._kSecAttrLabel = c_void_p.in_dll(self._security, "kSecAttrLabel")
        self._kSecAttrKeyClass = c_void_p.in_dll(self._security, "kSecAttrKeyClass")
        self._kSecReturnRef = c_void_p.in_dll(self._security, "kSecReturnRef")
        self._kSecMatchLimit = c_void_p.in_dll(self._security, "kSecMatchLimit")
        self._kSecMatchLimitAll = c_void_p.in_dll(self._security, "kSecMatchLimitAll")

        self._kSecAttrKeyTypeAES = c_void_p.in_dll(self._security, "kSecAttrKeyTypeAES")
        self._kSecAttrKeyTypeRSA = c_void_p.in_dll(self._security, "kSecAttrKeyTypeRSA")
        self._kSecAttrKeyTypeECDSA = c_void_p.in_dll(self._security, "kSecAttrKeyTypeECDSA")
        self._kSecAttrKeyClassPrivate = c_void_p.in_dll(self._security, "kSecAttrKeyClassPrivate")
        self._kSecAttrKeyClassPublic = c_void_p.in_dll(self._security, "kSecAttrKeyClassPublic")
        self._kSecAttrKeyClassSymmetric = c_void_p.in_dll(self._security, "kSecAttrKeyClassSymmetric")
        self._kSecDigestSHA2 = c_void_p.in_dll(self._security, "kSecDigestSHA2")

        self._kSecTransformInputAttributeName = c_void_p.in_dll(self._security, "kSecTransformInputAttributeName")
        self._kSecDigestTypeAttribute = c_void_p.in_dll(self._security, "kSecDigestTypeAttribute")
        self._kSecDigestLengthAttribute = c_void_p.in_dll(self._security, "kSecDigestLengthAttribute")

        self._kSecPaddingKey = c_void_p.in_dll(self._security, "kSecPaddingKey")
        self._kSecPaddingPKCS1Key = c_void_p.in_dll(self._security, "kSecPaddingPKCS1Key")
        self._kSecPaddingOAEPKey = c_void_p.in_dll(self._security, "kSecPaddingOAEPKey")

        self._kSecKeyPrintName = 1

        # enum values:
        self._kSecFormatOpenSSL = 1

    @staticmethod
    def get():
        """
        Get the static instance of Osx, creating it only when needed.
        """
        if Osx._instance == None:
            Osx._instance = Osx()
        return Osx._instance
