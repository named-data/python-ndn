import abc
from typing import List


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
