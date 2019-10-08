import abc
from typing import List
from .tlv_type import VarBinaryStr


__all__ = ['Signer']


class Signer(metaclass=abc.ABCMeta):
    __signers = {}

    @abc.abstractmethod
    def write_signature_info(self, signature_info):
        pass

    @abc.abstractmethod
    def get_signature_value_size(self):
        pass

    @abc.abstractmethod
    def write_signature_value(self, wire: VarBinaryStr, contents: List[VarBinaryStr]):
        pass
