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
import sys
import logging
from typing import Tuple, Optional
from ctypes import c_void_p, pointer, c_int
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA, ECC
from ...encoding import Signer, NonStrictName, Name, SignatureType, KeyLocator, BinaryStr, FormalName
from .tpm import Tpm
if sys.platform == 'darwin':
    from ...contrib.cocoapy import cf, CFSTR, ObjCInstance, cfstring_to_string, cfnumber_to_number, kCFNumberIntType
    from ...platform.osx import OsxSec, ReleaseGuard


class OsxSigner(Signer):
    def __init__(self, key_locator_name: NonStrictName, key_bits, key_type, key_ref):
        self.key_ref = key_ref
        self.key_locator_name = key_locator_name
        if key_type == cfstring_to_string(OsxSec().kSecAttrKeyTypeRSA):
            self.key_type = SignatureType.SHA256_WITH_RSA
            self.key_size = key_bits // 8
        elif key_type == cfstring_to_string(OsxSec().kSecAttrKeyTypeECSECPrimeRandom):
            self.key_type = SignatureType.SHA256_WITH_ECDSA
            self.key_size = (key_bits * 2 + 7) // 8
            self.key_size += self.key_size % 2
            self.key_size += 8
        else:
            raise ValueError(f'Unrecognized key type {key_type}')

    def write_signature_info(self, signature_info):
        signature_info.signature_type = self.key_type
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_locator_name

    def get_signature_value_size(self):
        return self.key_size

    def __del__(self):
        cf.CFRelease(self.key_ref)

    def write_signature_value(self, wire, contents) -> int:
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
            signature = sec.get_data(g.sig)
        real_len = len(signature)
        wire[:real_len] = signature
        return real_len


class TpmOsxKeychain(Tpm):
    @staticmethod
    def _get_key(key_name: NonStrictName):
        sec = OsxSec()
        with ReleaseGuard() as g:
            # TODO: what about name convension?
            logging.getLogger(__name__).debug('Get OSX Key %s' % Name.to_str(key_name))
            g.key_label = CFSTR(Name.to_str(key_name))
            g.query = ObjCInstance(cf.CFDictionaryCreateMutable(None, 6, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.query, sec.kSecClass, sec.kSecClassKey)
            cf.CFDictionaryAddValue(g.query, sec.kSecAttrLabel, g.key_label)
            cf.CFDictionaryAddValue(g.query, sec.kSecAttrKeyClass, sec.kSecAttrKeyClassPrivate)
            cf.CFDictionaryAddValue(g.query, sec.kSecReturnAttributes, sec.kCFBooleanTrue)
            cf.CFDictionaryAddValue(g.query, sec.kSecReturnRef, sec.kCFBooleanTrue)

            g.dic = c_void_p()
            ret = sec.security.SecItemCopyMatching(g.query, pointer(g.dic))
            if ret == sec.errSecItemNotFound:
                raise KeyError(f"Unable to find key {key_name}")
            elif ret != sec.errSecSuccess:
                raise RuntimeError(f"Error happened when searching specific key {key_name}")

            key_type = cfstring_to_string(cf.CFDictionaryGetValue(g.dic, sec.kSecAttrKeyType))
            key_bits = cfnumber_to_number(cf.CFDictionaryGetValue(g.dic, sec.kSecAttrKeySizeInBits))
            key_ref = cf.CFRetain(cf.CFDictionaryGetValue(g.dic, sec.kSecValueRef))
        return key_type, key_bits, key_ref

    def get_signer(self, key_name: NonStrictName, key_locator_name: Optional[NonStrictName] = None) -> Signer:
        key_type, key_bits, key_ref = self._get_key(key_name)
        if key_locator_name is None:
            key_locator_name = key_name
        return OsxSigner(key_locator_name, key_bits, key_type, key_ref)

    def key_exist(self, key_name: FormalName) -> bool:
        try:
            self._get_key(key_name)
            return True
        except KeyError:
            return False

    def delete_key(self, key_name: FormalName):
        sec = OsxSec()
        with ReleaseGuard() as g:
            logging.getLogger(__name__).debug('Delete OSX Key %s' % Name.to_str(key_name))
            g.key_label = CFSTR(Name.to_str(key_name))
            g.query = ObjCInstance(cf.CFDictionaryCreateMutable(None, 3, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.query, sec.kSecClass, sec.kSecClassKey)
            cf.CFDictionaryAddValue(g.query, sec.kSecAttrLabel, g.key_label)
            sec.security.SecItemDelete(g.query)

    @staticmethod
    def _convert_key_format(key_bits: BinaryStr, key_type: str):
        if key_type == 'rsa':
            return RSA.import_key(key_bits).export_key(format='DER')
        elif key_type == 'ec':
            xp = int.from_bytes(key_bits[1:33], 'big')
            yp = int.from_bytes(key_bits[33:], 'big')
            return ECC.construct(curve='P-256', point_x=xp, point_y=yp).export_key(format='DER')
        else:
            raise ValueError(f'Unsupported key type {key_type}')

    def generate_key(self, id_name: FormalName, key_type: str = 'rsa', **kwargs) -> Tuple[FormalName, BinaryStr]:
        sec = OsxSec()
        with ReleaseGuard() as g:
            logging.getLogger(__name__).debug('Generating OSX Key %s' % key_type)

            # Get key type and size
            if key_type == 'rsa':
                mac_key_type = sec.kSecAttrKeyTypeRSA
                key_size = c_int(kwargs.pop('key_size', 2048))
            elif key_type == 'ec':
                mac_key_type = sec.kSecAttrKeyTypeECSECPrimeRandom
                key_size = kwargs.pop('key_size', 256)
                if key_size != 256:
                    raise ValueError(f'Unsupported ECC curve P-{key_size}. Please use P-256.')
                key_size = c_int(key_size)
            else:
                raise ValueError(f'Unsupported key type {key_type}')
            g.key_size = cf.CFNumberCreate(None, kCFNumberIntType, pointer(key_size))

            # Generate private key
            g.pk_attr = ObjCInstance(cf.CFDictionaryCreateMutable(None, 1, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.pk_attr, sec.kSecAttrIsPermanent, sec.kCFBooleanTrue)

            g.attr = ObjCInstance(cf.CFDictionaryCreateMutable(None, 3, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.attr, sec.kSecAttrKeyType, mac_key_type)
            cf.CFDictionaryAddValue(g.attr, sec.kSecAttrKeySizeInBits, g.key_size)
            cf.CFDictionaryAddValue(g.attr, sec.kSecPrivateKeyAttrs, g.pk_attr)

            error = c_void_p()
            g.pri_key = sec.security.SecKeyCreateRandomKey(g.attr, pointer(error))
            if not g.pri_key:
                raise RuntimeError('Unable to create specific key')

            # Derive public key
            g.pub_key = sec.security.SecKeyCopyPublicKey(g.pri_key)
            g.pub_key_der = sec.security.SecKeyCopyExternalRepresentation(g.pub_key, pointer(error))
            if not g.pub_key_der:
                raise RuntimeError('Unable to export the public key')
            pub_key = self._convert_key_format(sec.get_data(g.pub_key_der), key_type)

            # Construct key name
            key_name = self.construct_key_name(id_name, pub_key, **kwargs)
            key_name_str = Name.to_str(key_name)
            g.key_label = CFSTR(Name.to_str(key_name_str))
            logging.getLogger(__name__).debug('Generated OSX Key %s' % key_name_str)

            # SecItemUpdate: kSecAttrLabel, kSecAttrAccessControl
            g.query = ObjCInstance(cf.CFDictionaryCreateMutable(None, 2, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.query, sec.kSecValueRef, g.pri_key)
            cf.CFDictionaryAddValue(g.query, sec.kSecClass, sec.kSecClassKey)

            g.update = ObjCInstance(cf.CFDictionaryCreateMutable(None, 2, cf.kCFTypeDictionaryKeyCallBacks, None))
            cf.CFDictionaryAddValue(g.update, sec.kSecAttrLabel, g.key_label)
            # Access cannot be changed in this way
            # g.access = c_void_p()
            # sec.security.SecAccessCreate(g.key_label, None, pointer(g.access))
            # g.acl = c_void_p()
            # sec.security.SecACLCreateWithSimpleContents(g.access, None, g.key_label, 0, pointer(g.acl))
            # cf.CFDictionaryAddValue(g.update, sec.kSecAttrAccess, g.access)

            ret = sec.security.SecItemUpdate(g.query, g.update)
            if ret != sec.errSecSuccess:
                raise RuntimeError('Unable to set the key label and access')
        return key_name, pub_key
