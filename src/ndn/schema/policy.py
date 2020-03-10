import abc
from typing import Optional
from ..encoding import SignaturePtrs, FormalName, InterestParam, BinaryStr
from ..encoding.signer import Signer
from ..types import Validator


class Policy:
    def __init__(self):
        self.node = None


class Cache(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def search(self, match, name: FormalName, param: InterestParam):
        pass

    @abc.abstractmethod
    async def save(self, match, name: FormalName, packet: BinaryStr):
        pass


class InterestValidator(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def validate(self, match, sig_ptrs: SignaturePtrs) -> bool:
        pass


class DataValidator(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    def get_validator(self, match) -> Validator:
        pass


class Signing(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def get_signer(self, match) -> Signer:
        pass


class InterestSigning(Signing, metaclass=abc.ABCMeta):
    pass


class DataSigning(Signing, metaclass=abc.ABCMeta):
    pass


class Encryption(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def decrypt(self, match, content: BinaryStr) -> Optional[BinaryStr]:
        pass

    @abc.abstractmethod
    async def encrypt(self, match, content: BinaryStr) -> Optional[BinaryStr]:
        pass


class InterestEncryption(Encryption, metaclass=abc.ABCMeta):
    pass


class DataEncryption(Encryption, metaclass=abc.ABCMeta):
    pass


class LocalOnly(Policy):
    pass


class Register(Policy):
    pass
