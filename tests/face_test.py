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
import asyncio

from ndn.client_conf import default_face
from ndn.transport.stream_face import TcpFace, UnixFace
from ndn.transport.udp_face import UdpFace


class TestFace:
    def test(self):
        url = 'unix:///tmp/nfd.sock'
        face = default_face(url)
        assert isinstance(face, UnixFace)
        assert face.path == '/tmp/nfd.sock'

        url = 'tcp://localhost'
        face = default_face(url)
        assert isinstance(face, TcpFace)
        assert face.host == 'localhost'
        assert face.port == 6363

        url = 'tcp4://localhost:6364'
        face = default_face(url)
        assert isinstance(face, TcpFace)
        assert face.host == 'localhost'
        assert face.port == 6364

        url = 'tcp6://localhost'
        face = default_face(url)
        assert isinstance(face, TcpFace)
        assert face.host == 'localhost'
        assert face.port == 6363

        url = 'udp://localhost'
        face = default_face(url)
        assert isinstance(face, UdpFace)
        assert face.host == 'localhost'
        assert face.port == 6363

        url = 'udp4://localhost:6364'
        face = default_face(url)
        assert isinstance(face, UdpFace)
        assert face.host == 'localhost'
        assert face.port == 6364

        url = 'udp6://localhost'
        face = default_face(url)
        assert isinstance(face, UdpFace)
        assert face.host == 'localhost'
        assert face.port == 6363

        url = 'udp6://[::1]:6465'
        face = default_face(url)
        assert isinstance(face, UdpFace)
        assert face.host == '::1'
        assert face.port == 6465

    def test_connection(self):
        url = 'udp://localhost'
        face = default_face(url)
        asyncio.run(face.open())

        url = 'udp4://localhost:6364'
        face = default_face(url)
        asyncio.run(face.open())

        url = 'udp6://localhost'
        face = default_face(url)
        asyncio.run(face.open())

        url = 'udp6://[::1]:6465'
        face = default_face(url)
        asyncio.run(face.open())
