import abc
from typing import Optional
from ndn.encoding import SignaturePtrs, FormalName, InterestParam, BinaryStr
from ndn.encoding.signer import Signer
from ndn.types import Validator
from .schema_tree import MatchedNode


class Policy:
    def __init__(self, parent):
        self.parent = parent


class Cache(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def search(self, match: MatchedNode, name: FormalName, param: InterestParam):
        pass

    @abc.abstractmethod
    async def save(self, match: MatchedNode, name: FormalName, packet: BinaryStr):
        pass


class InterestValidator(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def validate(self, match: MatchedNode, sig_ptrs: SignaturePtrs) -> bool:
        pass


class DataValidator(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def get_validator(self, match: MatchedNode) -> Validator:
        pass


class Signing(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def get_signer(self, match: MatchedNode) -> Signer:
        pass


class InterestSigning(Signing, metaclass=abc.ABCMeta):
    pass


class DataSigning(Signing, metaclass=abc.ABCMeta):
    pass


class Encryption(Policy, metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def decrypt(self, match: MatchedNode, content: BinaryStr) -> Optional[BinaryStr]:
        pass

    @abc.abstractmethod
    async def encrypt(self, match: MatchedNode, content: BinaryStr) -> Optional[BinaryStr]:
        pass


class InterestEncryption(Encryption, metaclass=abc.ABCMeta):
    pass


class DataEncryption(Encryption, metaclass=abc.ABCMeta):
    def get_encrypted_name(self, match: MatchedNode) -> FormalName:
        return match.name
