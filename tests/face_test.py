from socket import AF_INET, AF_INET6
from _pytest.config import main
import asyncio
from ndn.client_conf import default_face
from ndn.transport.stream_face import UnixFace, TcpFace
from ndn.transport.udp_face import UdpFace
from ndn.app import NDNApp
from ndn.encoding.tlv_var import parse_tl_num

def test():
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


def test_connection():
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
