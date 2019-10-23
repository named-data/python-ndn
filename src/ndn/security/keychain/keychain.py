import abc
from typing import Dict, Any


class Keychain:
    @abc.abstractmethod
    def get_signer(self, sign_args: Dict[str, Any]):
        pass
