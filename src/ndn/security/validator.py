import abc
from typing import Dict, Any
from ..encoding import FormalName, SignaturePtrs


class Validator(metaclass=abc.ABCMeta):
    @abc.abstractmethod
    async def interest_validate(self, name: FormalName, sig: SignaturePtrs) -> bool:
        pass

    @abc.abstractmethod
    async def data_validate(self, name: FormalName, sig: SignaturePtrs) -> bool:
        pass
