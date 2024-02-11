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
import ctypes as c
import logging
from typing import Tuple, Optional
from Cryptodome.PublicKey import ECC, RSA
from Cryptodome.Util.asn1 import DerSequence
from ndn.encoding import FormalName, BinaryStr

from ...encoding import Signer, NonStrictName, SignatureType, KeyLocator, Name
from .tpm import Tpm
if sys.platform == 'win32':
    from ...platform.windows import Cng, ReleaseGuard


class CngSigner(Signer):
    def __init__(self, key_locator_name: NonStrictName, sig_len, key_type, h_key):
        self.h_key = h_key
        self.key_locator_name = key_locator_name
        if key_type == "RSA":
            self.key_type = SignatureType.SHA256_WITH_RSA
            self.sig_len = sig_len
        elif key_type == "ECDSA":
            self.key_type = SignatureType.SHA256_WITH_ECDSA
            self.sig_len = sig_len + 8
        else:
            raise ValueError(f'Unrecognized key type {key_type}')

    def write_signature_info(self, signature_info):
        signature_info.signature_type = self.key_type
        signature_info.key_locator = KeyLocator()
        signature_info.key_locator.name = self.key_locator_name

    def get_signature_value_size(self):
        return self.sig_len

    def __del__(self):
        Cng().ncrypt.NCryptFreeObject(self.h_key)

    @staticmethod
    def _hash_contents(contents):
        cng = Cng()
        with ReleaseGuard() as defer:
            h_hash_alg = c.c_void_p()
            status = cng.bcrypt.BCryptOpenAlgorithmProvider(c.pointer(h_hash_alg), cng.BCRYPT_SHA256_ALGORITHM, 0, 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by BCryptOpenAlgorithmProvider')
            defer += lambda: cng.bcrypt.BCryptCloseAlgorithmProvider(h_hash_alg, 0)

            cb_hash_obj = c.c_ulong(0)
            cb_data = c.c_ulong(0)
            status = cng.bcrypt.BCryptGetProperty(h_hash_alg, cng.BCRYPT_OBJECT_LENGTH, c.pointer(cb_hash_obj), 4,
                                                  c.pointer(cb_data), 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by BCryptGetProperty')
            hash_obj = (c.c_byte * cb_hash_obj.value)()

            cb_hash = c.c_ulong(0)
            status = cng.bcrypt.BCryptGetProperty(h_hash_alg, cng.BCRYPT_HASH_LENGTH, c.pointer(cb_hash), 4,
                                                  c.pointer(cb_data), 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by BCryptGetProperty')
            hash_val = (c.c_byte * cb_hash.value)()

            h_hash = c.c_void_p()
            status = cng.bcrypt.BCryptCreateHash(h_hash_alg, c.pointer(h_hash), hash_obj, cb_hash_obj,
                                                 0, 0, 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by BCryptCreateHash')
            defer += lambda: cng.bcrypt.BCryptDestroyHash(h_hash)

            for blk in contents:
                status = cng.bcrypt.BCryptHashData(h_hash, c.c_char_p(bytes(blk)), len(blk), 0)
                if not cng.nt_success(status):
                    raise OSError(f'Error {status} returned by BCryptHashData')

            status = cng.bcrypt.BCryptFinishHash(h_hash, hash_val, cb_hash, 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by BCryptFinishHash')

            return hash_val, cb_hash

    def write_signature_value(self, wire, contents) -> int:
        cng = Cng()
        hash_val, cb_hash = self._hash_contents(contents)

        cb_signature = c.c_ulong()
        status = cng.ncrypt.NCryptSignHash(self.h_key, 0, hash_val, cb_hash, 0, 0,
                                           c.pointer(cb_signature), 0)
        if not cng.nt_success(status):
            raise OSError(f'Error {status} returned by NCryptSignHash')

        signature = (c.c_ubyte * cb_signature.value)()
        status = cng.ncrypt.NCryptSignHash(self.h_key, 0, hash_val, cb_hash, signature, cb_signature,
                                           c.pointer(cb_signature), 0)
        if not cng.nt_success(status):
            raise OSError(f'Error {status} returned by NCryptSignHash')

        if self.key_type == SignatureType.SHA256_WITH_ECDSA:
            der = DerSequence((int.from_bytes(signature[:cb_signature.value//2], 'big'),
                               int.from_bytes(signature[cb_signature.value//2:], 'big'))).encode()
        else:
            der = bytes(signature)

        real_len = len(der)
        wire[:real_len] = der
        return real_len


class TpmCng(Tpm):
    def __init__(self):
        cng = Cng()
        self.h_prov = c.c_void_p()
        # Try TPM2.0 platform key storage
        status = cng.ncrypt.NCryptOpenStorageProvider(c.pointer(self.h_prov), cng.MS_PLATFORM_KEY_STORAGE_PROVIDER, 0)
        if not cng.nt_success(status):
            # If failed, try software key storage
            status = cng.ncrypt.NCryptOpenStorageProvider(c.pointer(self.h_prov), cng.MS_KEY_STORAGE_PROVIDER, 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by NCryptOpenStorageProvider', status)

    def __del__(self):
        Cng().ncrypt.NCryptFreeObject(self.h_prov)

    @staticmethod
    def _convert_key_format(key_bits, key_type: str):
        if key_type == 'rsa':
            raise NotImplementedError('RSA on CNG is not implemented yet')
        elif key_type == 'ec':
            cng = Cng()
            pubkey_stru = c.cast(key_bits, c.POINTER(cng.BcryptEcckeyBlob))[0]
            base_idx = c.sizeof(cng.BcryptEcckeyBlob)
            key_x = int.from_bytes(key_bits[base_idx:base_idx + pubkey_stru.cb_key], 'big')
            key_y = int.from_bytes(key_bits[base_idx + pubkey_stru.cb_key:], 'big')
            return ECC.construct(curve='P-256', point_x=key_x, point_y=key_y).export_key(format='DER')
        else:
            raise ValueError(f'Unsupported key type {key_type}')

    def _get_key(self, key_label: str):
        cng = Cng()
        h_key = c.c_void_p()
        status = cng.ncrypt.NCryptOpenKey(self.h_prov, c.pointer(h_key), c.c_wchar_p(key_label), 0, 0)
        if not cng.nt_success(status):
            if status == cng.NTE_BAD_KEYSET:
                raise KeyError(f"Unable to find key with label {key_label}")
            else:
                raise OSError(f'Error {status} returned by NCryptOpenKey', status)

        cb_property = c.c_ulong(4)
        sig_len = c.c_ulong()
        status = cng.ncrypt.NCryptGetProperty(h_key, c.c_wchar_p('SignatureLength'), c.pointer(sig_len), cb_property,
                                              c.pointer(cb_property), 0)
        if not cng.nt_success(status):
            raise OSError(f'Error {status} returned by NCryptGetProperty', status)

        cb_property.value = 40
        key_type = (c.c_wchar * 20)()
        status = cng.ncrypt.NCryptGetProperty(h_key, c.c_wchar_p('AlgorithmName'), c.pointer(key_type), cb_property,
                                              c.pointer(cb_property), 0)
        if not cng.nt_success(status):
            raise OSError(f'Error {status} returned by NCryptGetProperty', status)

        return key_type.value, sig_len.value, h_key

    def get_signer(self, key_name: NonStrictName, key_locator_name: Optional[NonStrictName] = None) -> Signer:
        name_hash = Name.to_bytes(key_name).hex()
        key_type, sig_len, h_key = self._get_key(name_hash)
        if key_locator_name is None:
            key_locator_name = key_name
        return CngSigner(key_locator_name, sig_len, key_type, h_key)

    def key_exist(self, key_name: FormalName) -> bool:
        try:
            name_hash = Name.to_bytes(key_name).hex()
            self._get_key(name_hash)
            return True
        except KeyError:
            return False

    def delete_key(self, key_name: FormalName):
        name_hash = Name.to_bytes(key_name).hex()
        _, _, h_key = self._get_key(name_hash)
        Cng().ncrypt.NCryptDeleteKey(h_key, 0)

    @staticmethod
    def _convert_pub_key_format(key_bits: BinaryStr, key_type: str):
        if key_type == 'rsa':
            return RSA.import_key(key_bits).export_key(format='DER')
        elif key_type == 'ec':
            xp = int.from_bytes(key_bits[1:33], 'big')
            yp = int.from_bytes(key_bits[33:], 'big')
            return ECC.construct(curve='P-256', point_x=xp, point_y=yp).export_key(format='DER')
        else:
            raise ValueError(f'Unsupported key type {key_type}')

    def generate_key(self, id_name: FormalName, key_type: str = 'rsa', **kwargs) -> Tuple[FormalName, BinaryStr]:
        cng = Cng()
        with ReleaseGuard() as defer:
            logging.getLogger(__name__).debug('Generating CNG Key %s' % key_type)
            key_name = self.construct_key_name(id_name, b'', key_id_type='random')
            name_hash = Name.to_bytes(key_name).hex()

            if key_type == 'ec':
                algo = cng.NCRYPT_ECDSA_P256_ALGORITHM
            elif key_type == 'rsa':
                raise NotImplementedError('RSA on CNG is not implemented yet')
            else:
                raise ValueError(f'Unsupported key type {key_type}')

            h_key = c.c_void_p()
            status = cng.ncrypt.NCryptCreatePersistedKey(self.h_prov, c.pointer(h_key), algo,
                                                         c.c_wchar_p(name_hash), 0,
                                                         cng.NCRYPT_OVERWRITE_KEY_FLAG)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by NCryptCreatePersistedKey', status)
            defer += lambda: cng.ncrypt.NCryptFreeObject(h_key)

            status = cng.ncrypt.NCryptFinalizeKey(h_key, 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by NCryptFinalizeKey', status)

            if key_type == 'ec':
                prop = cng.BCRYPT_ECCPUBLIC_BLOB
            elif key_type == 'rsa':
                raise NotImplementedError('RSA on CNG is not implemented yet')
            else:
                raise ValueError(f'Unsupported key type {key_type}')

            cb_pubkey = c.c_ulong()
            status = cng.ncrypt.NCryptExportKey(h_key, 0, prop, 0, 0, 0, c.pointer(cb_pubkey), 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by NCryptExportKey', status)

            pubkey_blob = (c.c_ubyte * cb_pubkey.value)()
            status = cng.ncrypt.NCryptExportKey(h_key, 0, prop, 0, pubkey_blob, cb_pubkey, c.pointer(cb_pubkey), 0)
            if not cng.nt_success(status):
                raise OSError(f'Error {status} returned by NCryptExportKey', status)

            pub_key = self._convert_key_format(bytes(pubkey_blob), key_type)
        return key_name, bytes(pub_key)
