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
import sys
import logging
from ctypes import c_void_p, pointer
from Cryptodome.Hash import SHA256
from ...encoding import Signer, NonStrictName, Name, SignatureType, KeyLocator
from .tpm import Tpm
if sys.platform == 'darwin':
    from ...contrib.cocoapy import cf, CFSTR, ObjCInstance, cfstring_to_string, cfnumber_to_number
    from ...contrib.osx.security import OsxSec, ReleaseGuard


class OsxSigner(Signer):
    def __init__(self, key_name, key_bits, key_type, key_ref):
        self.key_ref = key_ref
        self.key_name = key_name
        if key_type == cfstring_to_string(OsxSec().kSecAttrKeyTypeRSA):
            self.key_type = SignatureType.SHA256_WITH_RSA
            self.key_size = key_bits // 8
        elif key_type == cfstring_to_string(OsxSec().kSecAttrKeyTypeECSECPrimeRandom):
            self.key_type = SignatureType.SHA256_WITH_ECDSA
            self.key_size = (key_bits * 2 + 7) // 8
            self.key_size += self.key_size % 2
        else:
            raise ValueError(f'Unrecognized key type {key_type}')

    def write_signature_info(self, signature_info):
        signature_info.signature_type = self.key_type
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_name

    def get_signature_value_size(self):
        return self.key_size

    def __del__(self):
        cf.CFRelease(self.key_ref)

    def write_signature_value(self, wire, contents):
        h = SHA256.new()
        for blk in contents:
            h.update(blk)

        # KeyDigest
        sec = OsxSec()
        with ReleaseGuard() as g:
            g.digest = sec.create_data(h.digest())
            error = c_void_p()
            if self.key_type == SignatureType.SHA256_WITH_RSA:
                algo = sec.kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256
            else:
                algo = sec.kSecKeyAlgorithmECDSASignatureDigestX962SHA256
            g.sig = sec.security.SecKeyCreateSignature(self.key_ref, algo, g.digest, pointer(error))
            if error.value is not None:
                raise RuntimeError('Create signature failed')
            wire[:] = sec.get_data(g.sig)


class TpmOsxKeychain(Tpm):
    def get_signer(self, key_name: NonStrictName) -> Signer:
        sec = OsxSec()
        with ReleaseGuard() as g:
            logging.debug('Get OSX Key %s' % Name.to_str(key_name))
            g.key_label = CFSTR(Name.to_str(key_name))
            g.query = ObjCInstance(cf.CFDictionaryCreateMutable(None, 6, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.query, sec.kSecClass, sec.kSecClassKey)
            cf.CFDictionaryAddValue(g.query, sec.kSecAttrLabel, g.key_label)
            cf.CFDictionaryAddValue(g.query, sec.kSecAttrKeyClass, sec.kSecAttrKeyClassPrivate)
            cf.CFDictionaryAddValue(g.query, sec.kSecReturnAttributes, sec.kCFBooleanTrue)
            cf.CFDictionaryAddValue(g.query, sec.kSecReturnRef, sec.kCFBooleanTrue)

            g.dic = c_void_p()
            ret = sec.security.SecItemCopyMatching(g.query, pointer(g.dic))
            if ret:
                raise ValueError(f"Unable to load specific key {key_name}")

            key_type = cfstring_to_string(cf.CFDictionaryGetValue(g.dic, sec.kSecAttrKeyType))
            key_bits = cfnumber_to_number(cf.CFDictionaryGetValue(g.dic, sec.kSecAttrKeySizeInBits))
            key_ref = cf.CFRetain(cf.CFDictionaryGetValue(g.dic, sec.kSecValueRef))

            return OsxSigner(key_name, key_bits, key_type, key_ref)
