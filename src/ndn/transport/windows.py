import os
import aenum
import socket
import asyncio as aio
import ctypes as ct


class sockaddr_un(ct.Structure):
    _fields_ = [("sun_family", ct.c_ushort), ("sun_path", ct.c_char * 108)]


aenum.extend_enum(socket.AddressFamily, "AF_UNIX", 1)
AF_UNIX = socket.AddressFamily(1)
NULL = 0


def iocp_connect(proactor, conn, address):
    # _overlapped.WSAConnect(conn.fileno(), address)
    addr = sockaddr_un(AF_UNIX.value, address.encode() + b"\0")
    winsock = ct.windll.ws2_32
    winsock.connect(conn.fileno(), addr, 110)

    fut = proactor._loop.create_future()
    fut.set_result(None)
    return fut


async def create_unix_connection(
        loop, protocol_factory, path=None, *,
        ssl=None, sock=None,
        server_hostname=None,
        ssl_handshake_timeout=None):
    assert server_hostname is None or isinstance(server_hostname, str)
    if ssl:
        if server_hostname is None:
            raise ValueError(
                'you have to pass server_hostname when using ssl')
    else:
        if server_hostname is not None:
            raise ValueError('server_hostname is only meaningful with ssl')
        if ssl_handshake_timeout is not None:
            raise ValueError(
                'ssl_handshake_timeout is only meaningful with ssl')

    if path is not None:
        if sock is not None:
            raise ValueError(
                'path and sock can not be specified at the same time')

        path = os.fspath(path)
        sock = socket.socket(AF_UNIX, socket.SOCK_STREAM, 0)
        try:
            sock.setblocking(False)
            # await loop.sock_connect(sock, path)
            await iocp_connect(loop._proactor, sock, path)
        except:
            sock.close()
            raise

    else:
        if sock is None:
            raise ValueError('no path and sock were specified')
        if (sock.family != AF_UNIX or
                sock.type != socket.SOCK_STREAM):
            raise ValueError(
                f'A UNIX Domain Stream Socket was expected, got {sock!r}')
        sock.setblocking(False)

    transport, protocol = await loop._create_connection_transport(
        sock, protocol_factory, ssl, server_hostname,
        ssl_handshake_timeout=ssl_handshake_timeout)
    return transport, protocol


async def open_unix_connection(path=None, *,
                                limit=2 ** 16, **kwds):
    """Similar to `open_connection` but works with UNIX Domain Sockets."""
    loop = aio.events.get_running_loop()

    reader = aio.StreamReader(limit=limit, loop=loop)
    protocol = aio.StreamReaderProtocol(reader, loop=loop)
    transport, _ = await create_unix_connection(
        loop, lambda: protocol, path, **kwds)
    writer = aio.StreamWriter(transport, protocol, reader, loop)
    return reader, writer
