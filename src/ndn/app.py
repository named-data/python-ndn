# -----------------------------------------------------------------------------
# Copyright (C) 2019-2020 Xinyu Ma
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
import struct
import logging
import asyncio as aio
from typing import Optional, Any, Awaitable, Coroutine, Tuple, List
from .utils import gen_nonce
from .encoding import BinaryStr, TypeNumber, LpTypeNumber, parse_interest, \
    parse_network_nack, parse_data, DecodeError, Name, NonStrictName, MetaInfo, \
    make_data, InterestParam, make_interest, FormalName, SignaturePtrs
from .security import Keychain, sha256_digest_checker, params_sha256_checker
from .transport.stream_socket import Face
from .app_support.nfd_mgmt import make_command, parse_response
from .name_tree import NameTrie, InterestTreeNode, PrefixTreeNode
from .types import NetworkError, InterestTimeout, Validator, Route, InterestCanceled, \
    InterestNack, ValidationFailure
from .client_conf import read_client_conf, default_face, default_keychain


class NDNApp:
    """
    An NDN application.

    :ivar face: the Face used to connection to a NFD node.
    :ivar keychain: the Keychain to store Identities and Keys, providing Signers.
    :ivar int_validator: the default validator for Interest packets.
    :ivar data_validator: the default validator for Data packets.
    """
    face: Face = None
    keychain: Keychain = None
    _int_tree: NameTrie = None
    _prefix_tree: NameTrie = None
    int_validator: Validator = None
    data_validator: Validator = None
    _autoreg_routes: List[Tuple[FormalName, Route, Optional[Validator], bool, bool]]

    def __init__(self, face=None, keychain=None):
        config = read_client_conf() if not face or not keychain else {}
        if face is not None:
            self.face = face
        else:
            self.face = default_face(config['transport'])
        self.face.callback = self._receive
        if keychain is not None:
            self.keychain = keychain
        else:
            self.keychain = default_keychain(config['pib'], config['tpm'])
        self._int_tree = NameTrie()
        self._prefix_tree = NameTrie()
        self.data_validator = sha256_digest_checker
        self.int_validator = sha256_digest_checker
        self._autoreg_routes = []

    async def _receive(self, typ: int, data: BinaryStr):
        """
        Pipeline when a packet is received.

        :param typ: the Type.
        :param data: the Value of the packet without TL.
        """
        logging.debug('Packet received %s, %s' % (typ, bytes(data)))
        if typ == TypeNumber.INTEREST:
            try:
                name, param, app_param, sig = parse_interest(data, with_tl=True)
            except (DecodeError, TypeError, ValueError, struct.error):
                logging.warning('Unable to decode received packet')
                return
            logging.debug('Interest received %s' % Name.to_str(name))
            await self._on_interest(name, param, app_param, sig, raw_packet=data)
        elif typ == TypeNumber.DATA:
            try:
                name, meta_info, content, sig = parse_data(data, with_tl=True)
            except (DecodeError, TypeError, ValueError, struct.error):
                logging.warning('Unable to decode received packet')
                return
            logging.debug('Data received %s' % Name.to_str(name))
            await self._on_data(name, meta_info, content, sig, raw_packet=data)
        elif typ == LpTypeNumber.LP_PACKET:
            try:
                nack_reason, interest = parse_network_nack(data, with_tl=True)
                name, _, _, _ = parse_interest(interest, with_tl=True)
            except (DecodeError, TypeError, ValueError, struct.error):
                logging.warning('Unable to decode received packet')
                return
            logging.debug('NetworkNack received %s, reason=%s' % (Name.to_str(name), nack_reason))
            self._on_nack(name, nack_reason)
        else:
            logging.warning('Unable to decode received packet')

    def put_raw_packet(self, data: BinaryStr):
        r"""
        Send a raw Data packet.

        :param data: TLV encoded Data packet.
        :type data: :any:`BinaryStr`
        :raises NetworkError: the face to NFD is down.
        """
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        self.face.send(data)

    def prepare_data(self, name: NonStrictName, content: Optional[BinaryStr] = None, **kwargs):
        r"""
        Prepare a Data packet by generating, encoding and signing it.

        :param name: the Name.
        :type name: :any:`NonStrictName`
        :param content: the Content.
        :type content: Optional[:any:`BinaryStr`]
        :param kwargs: :ref:`label-keyword-arguments`.
        :return: TLV encoded Data packet.
        """
        if 'signer' in kwargs:
            signer = kwargs['signer']
        else:
            signer = self.keychain.get_signer(kwargs)
        if 'meta_info' in kwargs:
            meta_info = kwargs['meta_info']
        else:
            meta_info = MetaInfo.from_dict(kwargs)
        return make_data(name, meta_info, content, signer=signer)

    def put_data(self, name: NonStrictName, content: Optional[BinaryStr] = None, **kwargs):
        r"""
        Publish a Data packet.

        :param name: the Name.
        :type name: :any:`NonStrictName`
        :param content: the Content.
        :type content: Optional[:any:`BinaryStr`]
        :param kwargs: :ref:`label-keyword-arguments`.
        :return: TLV encoded Data packet.
        """
        self.put_raw_packet(self.prepare_data(name, content, **kwargs))

    def express_interest(self,
                         name: NonStrictName,
                         app_param: Optional[BinaryStr] = None,
                         validator: Optional[Validator] = None,
                         need_raw_packet: bool = False,
                         **kwargs) -> Coroutine[Any, None, Tuple[FormalName, MetaInfo, Optional[BinaryStr]]]:
        r"""
        Express an Interest packet.

        The Interest packet is sent immediately and a coroutine used to get the result is returned.
        Awaiting on what is returned will block until the Data is received and return that Data.
        An exception is raised if unable to receive the Data.

        :param name: the Name.
        :type name: :any:`NonStrictName`
        :param app_param: the ApplicationParameters.
        :type app_param: Optional[:any:`BinaryStr`]
        :param validator: the Validator used to verify the Data received.
        :type validator: Optional[:any:`Validator`]
        :param need_raw_packet: if True, return the raw Data packet with TL.
        :type need_raw_packet: bool
        :param kwargs: :ref:`label-keyword-arguments`.
        :return: A tuple of (Name, MetaInfo, Content) after ``await``.
            If need_raw_packet is True, return a tuple (Name, MetaInfo, Content, RawPacket).
        :rtype: Coroutine[Any, None, Tuple[:any:`FormalName`, :any:`MetaInfo`, Optional[:any:`BinaryStr`]]]

        The following exception is raised by ``express_interest``:

        :raises NetworkError: the face to NFD is down before sending this Interest.

        The following exceptions are raised by the coroutine returned:

        :raises InterestNack: an NetworkNack is received.
        :raises InterestTimeout: time out.
        :raises ValidationFailure: unable to validate the Data packet.
        :raises InterestCanceled: the face to NFD is shut down after sending this Interest.
        """
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        if 'signer' in kwargs:
            signer = kwargs['signer']
        elif app_param is not None:
            signer = self.keychain.get_signer(kwargs)
        else:
            signer = None
        if 'interest_param' in kwargs:
            interest_param = kwargs['interest_param']
        else:
            if 'nonce' not in kwargs:
                kwargs['nonce'] = gen_nonce()
            interest_param = InterestParam.from_dict(kwargs)
        interest, final_name = make_interest(name, interest_param, app_param, signer=signer, need_final_name=True)
        future = aio.get_event_loop().create_future()
        node = self._int_tree.setdefault(final_name, InterestTreeNode())
        node.append_interest(future, interest_param)
        self.face.send(interest)
        return self._wait_for_data(future, interest_param.lifetime, final_name, node, validator, need_raw_packet)

    async def _wait_for_data(self, future: aio.Future, lifetime: int, name: FormalName,
                             node: InterestTreeNode, validator: Validator, need_raw_packet: bool):
        lifetime = 100 if lifetime is None else lifetime
        try:
            name, meta_info, content, sig, raw_packet = await aio.wait_for(future, timeout=lifetime/1000.0)
        except aio.TimeoutError:
            if node.timeout(future):
                del self._int_tree[name]
            raise InterestTimeout()
        except aio.CancelledError:
            raise InterestCanceled()
        if validator is None:
            validator = self.data_validator
        if await validator(name, sig):
            if need_raw_packet:
                return name, meta_info, content, raw_packet
            else:
                return name, meta_info, content
        else:
            raise ValidationFailure(name, meta_info, content)

    async def main_loop(self, after_start: Awaitable = None):
        """
        The main loop of NDNApp.

        :param after_start: the coroutine to start after connection to NFD is established.
        """
        async def starting_task():
            for name, route, validator, need_raw_packet, need_sig_ptrs in self._autoreg_routes:
                await self.register(name, route, validator, need_raw_packet, need_sig_ptrs)
            if after_start:
                try:
                    await after_start
                except Exception:
                    self.face.shutdown()
                    raise

        try:
            await self.face.open()
        except (FileNotFoundError, ConnectionError, OSError, PermissionError):
            if after_start:
                if isinstance(after_start, Coroutine):
                    after_start.close()
                elif isinstance(after_start, aio.Task) or isinstance(after_start, aio.Future):
                    after_start.cancel()
            raise
        task = aio.ensure_future(starting_task())
        logging.debug('Connected to NFD node, start running...')
        await self.face.run()
        self.face.shutdown()
        self._clean_up()
        await task

    def _clean_up(self):
        for node in self._int_tree.itervalues():
            node.cancel()
        self._prefix_tree.clear()
        self._int_tree.clear()

    def shutdown(self):
        """
        Manually shutdown the face to NFD.
        """
        logging.info('Manually shutdown')
        self.face.shutdown()

    def run_forever(self, after_start: Awaitable = None) -> bool:
        """
        A non-async wrapper of :meth:`main_loop`.

        :param after_start: the coroutine to start after connection to NFD is established.

        :examples:
            .. code-block:: python3

                app = NDNApp()

                if __name__ == '__main__':
                    app.run_forever(after_start=main())
        """
        task = self.main_loop(after_start)
        try:
            aio.get_event_loop().run_until_complete(task)
            ret = True
        except KeyboardInterrupt:
            logging.info('Receiving Ctrl+C, shutdown')
            ret = False
        finally:
            self.face.shutdown()
        logging.debug('Face is down now')
        return ret

    def route(self, name: NonStrictName, validator: Optional[Validator] = None,
              need_raw_packet: bool = False, need_sig_ptrs: bool = False):
        """
        A decorator used to register a permanent route for a specific prefix.

        This function is non-blocking and can be called at any time.
        If it is called before connecting to NFD, NDNApp will remember this route and
        automatically register it every time when a connection is established.
        Failure in registering this route to NFD will be ignored.

        The decorated function should accept 3 arguments: Name, Interest parameters and ApplicationParameters.

        :param name: the Name prefix for this route.
        :type name: :any:`NonStrictName`
        :param validator: the Validator used to validate coming Interests.
            An Interest without ApplicationParameters and SignatureInfo will be considered valid without
            calling validator.
            Interests with malformed ParametersSha256DigestComponent will be dropped before going into the validator.
            Otherwise NDNApp will try to validate the Interest with the validator.
            Interests which fail to be validated will be dropped without raising any exception.
        :type validator: Optional[:any:`Validator`]
        :param need_raw_packet: if True, pass the raw Interest packet to the callback as a keyword argument
            ``raw_packet``.
        :type need_raw_packet: bool
        :param need_sig_ptrs: if True, pass the Signature pointers to the callback as a keyword argument
            ``sig_ptrs``.
        :type need_sig_ptrs: bool

        :examples:
            .. code-block:: python3

                app = NDNApp()

                @app.route('/example/rpc')
                def on_interest(name: FormalName, param: InterestParam, app_param):
                    pass
        """
        name = Name.normalize(name)

        def decorator(func: Route):
            self._autoreg_routes.append((name, func, validator, need_raw_packet, need_sig_ptrs))
            if self.face.running:
                aio.ensure_future(self.register(name, func, validator, need_raw_packet, need_sig_ptrs))
            return func
        return decorator

    async def register(self, name: NonStrictName, func: Route, validator: Optional[Validator] = None,
                       need_raw_packet: bool = False, need_sig_ptrs: bool = False):
        """
        Register a route for a specific prefix dynamically.

        :param name: the Name prefix for this route.
        :type name: :any:`NonStrictName`
        :param func: the onInterest function for the specified route.
        :type func: Callable[[:any:`FormalName`, :any:`InterestParam`, Optional[:any:`BinaryStr`]], ``None``]
        :param validator: the Validator used to validate coming Interests.
        :type validator: Optional[:any:`Validator`]
        :return: ``True`` if the registration succeeded.
        :param need_raw_packet: if True, pass the raw Interest packet to the callback as a keyword argument
            ``raw_packet``.
        :type need_raw_packet: bool
        :param need_sig_ptrs: if True, pass the Signature pointers to the callback as a keyword argument
            ``sig_ptrs``.
        :type need_sig_ptrs: bool

        :raises ValueError: the prefix is already registered.
        :raises NetworkError: the face to NFD is down now.
        """
        name = Name.normalize(name)
        node = self._prefix_tree.setdefault(name, PrefixTreeNode())
        if node.callback:
            raise ValueError(f'Duplicated registration: {Name.to_str(name)}')
        node.callback = func
        node.extra_param = {'raw_packet': need_raw_packet, 'sig_ptrs': need_sig_ptrs}
        if validator:
            node.validator = validator
        try:
            _, _, reply = await self.express_interest(make_command('rib', 'register', name=name), lifetime=1000)
            ret = parse_response(reply)
            if ret['status_code'] != 200:
                logging.error(f'Registration for {Name.to_str(name)} failed: '
                              f'{ret["status_code"]} {bytes(ret["status_text"]).decode()}')
                return False
            else:
                logging.debug(f'Registration for {Name.to_str(name)} succeeded: '
                              f'{ret["status_code"]} {bytes(ret["status_text"]).decode()}')
                return True
        except (InterestNack, InterestTimeout, InterestCanceled, ValidationFailure) as e:
            logging.error(f'Registration for {Name.to_str(name)} failed: {e.__class__.__name__}')
            return False

    async def unregister(self, name: NonStrictName):
        """
        Unregister a route for a specific prefix.

        :param name: the Name prefix.
        :type name: :any:`NonStrictName`
        """
        name = Name.normalize(name)
        del self._prefix_tree[name]
        await self.express_interest(make_command('rib', 'unregister', name=name), lifetime=1000)

    def _on_nack(self, name: FormalName, nack_reason: int):
        node = self._int_tree[name]
        if node:
            if node.nack_interest(nack_reason):
                del self._int_tree[name]

    async def _on_data(self, name: FormalName, meta_info: MetaInfo,
                       content: Optional[BinaryStr], sig: SignaturePtrs, raw_packet):
        clean_list = []
        for prefix, node in self._int_tree.prefixes(name):
            if node.satisfy((name, meta_info, content, sig, raw_packet), prefix != name):
                clean_list.append(prefix)
        for prefix in clean_list:
            del self._int_tree[prefix]

    async def _on_interest(self, name: FormalName, param: InterestParam,
                           app_param: Optional[BinaryStr], sig: SignaturePtrs, raw_packet: BinaryStr):
        trie_step = self._prefix_tree.longest_prefix(name)
        if not trie_step:
            logging.warning('No route: %s' % name)
            return
        node = trie_step.value
        if app_param is not None or sig.signature_info is not None:
            if not await params_sha256_checker(name, sig):
                logging.warning('Drop malformed Interest: %s' % name)
                return
        if sig.signature_info is not None:
            validator = node.validator if node.validator else self.int_validator
            valid = await validator(name, sig)
        else:
            valid = True
        if not valid:
            logging.warning('Drop unvalidated Interest: %s' % name)
            return
        if node.extra_param:
            kwargs = {}
            if node.extra_param.get('raw_packet', False):
                kwargs['raw_packet'] = raw_packet
            if node.extra_param.get('sig_ptrs', False):
                kwargs['sig_ptrs'] = sig
            node.callback(name, param, app_param, **kwargs)
        else:
            node.callback(name, param, app_param)
