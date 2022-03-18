## WIP
from typing import Callable
from ...encoding import Component, BinaryStr


UserFn = Callable[[BinaryStr], bool]


class Validator:
    pass


def make_validator(lvs_text: str, user_fns: dict[str, UserFn], trust_anchor: BinaryStr):
    pass
