## WIP
from typing import Callable
from ...encoding import Component, BinaryStr


# Compile embedded rule names, into a tree
# Validate: all rules are defined (DAG), pattern variable checker order,
#           all chains are a DAG
# Checker:  all user functions are defined,
#           all chains are from trust anchor and thus a forest
# Put checker into the place of pattern


## WIP


UserFn = Callable[[BinaryStr, list[BinaryStr]], bool]


class Validator:
    pass


def make_validator(lvs_text: str, user_fns: dict[str, UserFn], trust_anchor: BinaryStr):
    pass
