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
import abc
from typing import Any, Callable, Coroutine


class Face(metaclass=abc.ABCMeta):
    running: bool = False
    callback: Callable[[int, bytes], Coroutine[Any, None, None]] = None

    def __init__(self):
        self.running = False

    @abc.abstractmethod
    async def open(self):
        pass

    # TODO: Should switch to async function, since some requires gracefully shutdown
    @abc.abstractmethod
    def shutdown(self):
        pass

    @abc.abstractmethod
    def send(self, data: bytes):
        pass

    @abc.abstractmethod
    async def run(self):
        pass

    @abc.abstractmethod
    async def isLocalFace(self):
        pass
