# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
import time
from random import randint


def timestamp():
    """
    Generate a timestamp number.

    :return: the time in milliseconds since the epoch as an integer
    """
    return int(time.time() * 1000)


def gen_nonce():
    """
    Generate a random nonce.

    :return: a random 32-bit unsigned integer.
    """
    return randint(1, 2 ** 32 - 1)


def gen_nonce_64():
    """
    Generate a random 64-bit nonce.

    :return: a random 64-bit unsigned integer.
    """
    return randint(1, 2 ** 64 - 1)
