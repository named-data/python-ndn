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
from socket import AF_INET, AF_INET6, gaierror, getaddrinfo

from .face import Face


class IpFace(Face):

    def isLocalFace(self):
        local_checker = {AF_INET: lambda x: x.startswith('127'),
                         AF_INET6: lambda x: x == '::1'}
        try:
            r = getaddrinfo(self.host, self.port)
        except gaierror:
            return False
        for res_family, _, _, _, addr in r:
            if not local_checker[res_family](addr[0]):
                return False
        return True
