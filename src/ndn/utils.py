# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 The python-ndn authors
#
# This file is part of python-ndn.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
