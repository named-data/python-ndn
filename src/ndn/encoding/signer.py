import abc
from typing import List
import hashlib


class Signer(metaclass=abc.ABCMeta):
    __signers = {}

    @abc.abstractmethod
    def write_signature_info(self, signature_info, **kwargs):
        pass

    @abc.abstractmethod
    def get_signature_value_size(self, **kwargs):
        pass

    @abc.abstractmethod
    def write_signature_value(self, wire: memoryview, contents: List[memoryview], **kwargs):
        pass

    @staticmethod
    def register(typ: int, signer) -> bool:
        if typ > 0xFF:
            raise ValueError('current encoding function cannot deal with multibyte signature type')
        if isinstance(signer, Signer):
            if typ not in Signer.__signers:
                Signer.__signers[typ] = signer
                return True
            else:
                return False
        else:
            raise TypeError('only instances of Signer can be registered')

    @staticmethod
    def get_signer(typ: int):
        return Signer.__signers[typ]


class DigestSha256(Signer):
    def write_signature_info(self, signature_info, **kwargs):
        print("wrt info", kwargs)
        return

    def get_signature_value_size(self, **kwargs):
        print("wrt size", kwargs)
        return 32

    def write_signature_value(self, wire: memoryview, contents: List[memoryview], **kwargs):
        print("wrt value", kwargs)
        algo = hashlib.sha256()
        for blk in contents:
            algo.update(blk)
        wire[0:32] = algo.digest()
