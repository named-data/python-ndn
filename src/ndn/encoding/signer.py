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
