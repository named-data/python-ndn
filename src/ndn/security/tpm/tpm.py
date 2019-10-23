import abc
from ...encoding import Signer


class Tpm(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_signer(self, key_name: bytes) -> Signer:
        pass
