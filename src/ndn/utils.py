import time
from random import randint


def timestamp():
    return int(time.time() * 1000)


def gen_nonce():
    return randint(1, 2 ** 32 - 1)


def gen_nonce_64():
    return randint(1, 2 ** 64 - 1)
