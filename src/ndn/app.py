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
import struct
import logging
import asyncio as aio
from typing import Optional, Any, Awaitable, Coroutine, Tuple, List
from .utils import gen_nonce
from .encoding import BinaryStr, TypeNumber, LpTypeNumber, parse_interest, \
    parse_tl_num, parse_data, DecodeError, Name, NonStrictName, MetaInfo, \
    make_data, InterestParam, make_interest, FormalName, SignaturePtrs, parse_lp_packet, Component
from .security import Keychain, sha256_digest_checker, params_sha256_checker, NullSigner
from .transport.face import Face
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
    _prefix_register_semaphore: aio.Semaphore = None
    logger: logging.Logger

    def __init__(self, face=None, keychain=None):
        self.logger = logging.getLogger(__name__)
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
        :param data: the Value of the packet with TL.
        """
        # if self.logger.isEnabledFor(logging.DEBUG):
        #     self.logger.debug('Packet received %s, %s' % (typ, bytes(data)))
        if typ == LpTypeNumber.LP_PACKET:
            try:
                nack_reason, fragment = parse_lp_packet(data, with_tl=True)
            except (DecodeError, TypeError, ValueError, struct.error):
                self.logger.warning('Unable to decode received packet')
                return
            data = fragment
            typ, _ = parse_tl_num(data)
        else:
            nack_reason = None

        if nack_reason is not None:
            try:
                name, _, _, _ = parse_interest(data, with_tl=True)
            except (DecodeError, TypeError, ValueError, struct.error):
                self.logger.warning('Unable to decode the fragment of LpPacket')
                return
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug('NetworkNack received %s, reason=%s' % (Name.to_str(name), nack_reason))
            self._on_nack(name, nack_reason)
        else:
            if typ == TypeNumber.INTEREST:
                try:
                    name, param, app_param, sig = parse_interest(data, with_tl=True)
                except (DecodeError, TypeError, ValueError, struct.error):
                    self.logger.warning('Unable to decode received packet')
                    return
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug('Interest received %s' % Name.to_str(name))
                await self._on_interest(name, param, app_param, sig, raw_packet=data)
            elif typ == TypeNumber.DATA:
                try:
                    name, meta_info, content, sig = parse_data(data, with_tl=True)
                except (DecodeError, TypeError, ValueError, struct.error):
                    self.logger.warning('Unable to decode received packet')
                    return
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug('Data received %s' % Name.to_str(name))
                await self._on_data(name, meta_info, content, sig, raw_packet=data)
            else:
                self.logger.warning('Unable to decode received packet')

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
        if kwargs.get('no_signature', False):
            signer = NullSigner()
        elif 'signer' in kwargs:
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
        return self.express_raw_interest(final_name, interest_param, interest, validator, need_raw_packet)

    def express_raw_interest(self,
                             final_name: NonStrictName,
                             interest_param: InterestParam,
                             raw_interest: BinaryStr,
                             validator: Optional[Validator] = None,
                             need_raw_packet: bool = False
                             ) -> Coroutine[Any, None, Tuple[FormalName, MetaInfo, Optional[BinaryStr]]]:
        final_name = Name.normalize(final_name)
        future = aio.get_running_loop().create_future()
        if Component.get_type(final_name[-1]) == Component.TYPE_IMPLICIT_SHA256:
            node_name = final_name[:-1]
            implicit_sha256 = Component.get_value(final_name[-1])
        else:
            node_name = final_name
            implicit_sha256 = b''
        node = self._int_tree.setdefault(node_name, InterestTreeNode())
        node.append_interest(future, interest_param, implicit_sha256)
        self.face.send(raw_interest)
        return self._wait_for_data(future, interest_param.lifetime, node_name, node, validator, need_raw_packet)

    async def _wait_for_data(self, future: aio.Future, lifetime: int, node_name: FormalName,
                             node: InterestTreeNode, validator: Validator, need_raw_packet: bool):
        lifetime = 100 if lifetime is None else lifetime
        try:
            data_name, meta_info, content, sig, raw_packet = await aio.wait_for(future, timeout=lifetime/1000.0)
        except aio.TimeoutError:
            if node.timeout(future):
                del self._int_tree[node_name]
            raise InterestTimeout()
        except aio.CancelledError:
            raise InterestCanceled()
        if validator is None:
            validator = self.data_validator
        if await validator(data_name, sig):
            if need_raw_packet:
                return data_name, meta_info, content, raw_packet
            else:
                return data_name, meta_info, content
        else:
            raise ValidationFailure(data_name, meta_info, content, sig)

    async def main_loop(self, after_start: Awaitable = None) -> bool:
        """
        The main loop of NDNApp.

        :param after_start: the coroutine to start after connection to NFD is established.
        :return: ``True`` if the connection is shutdown not by ``Ctrl+C``.
            For example, manually or by the other side.
        """
        self._prefix_register_semaphore = aio.Semaphore(1)

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
                elif isinstance(after_start, (aio.Task, aio.Future)):
                    after_start.cancel()
            raise
        task = aio.create_task(starting_task())
        self.logger.debug('Connected to NFD node, start running...')
        try:
            await self.face.run()
            ret = True
        except aio.CancelledError:
            self.logger.info('Shutting down')
            ret = False
        finally:
            self.face.shutdown()
        self._clean_up()
        await task
        return ret

    def _clean_up(self):
        for node in self._int_tree.itervalues():
            node.cancel()
        self._prefix_tree.clear()
        self._int_tree.clear()

    def shutdown(self):
        """
        Manually shutdown the face to NFD.
        """
        self.logger.info('Manually shutdown')
        self.face.shutdown()

    def run_forever(self, after_start: Awaitable = None):
        """
        A non-async wrapper of :meth:`main_loop`.

        :param after_start: the coroutine to start after connection to NFD is established.

        :examples:
            .. code-block:: python3

                app = NDNApp()

                if __name__ == '__main__':
                    app.run_forever(after_start=main())
        """
        try:
            aio.run(self.main_loop(after_start))
        except KeyboardInterrupt:
            self.logger.info('Receiving Ctrl+C, exit')

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

        .. note::
            The route function must be a normal function instead of an ``async`` one.
            This is on purpose, because an Interest is supposed to be replied ASAP,
            even it cannot finish the request in time.
            To provide some feedback, a better practice is replying with an Application NACK
            (or some equivalent Data packet saying the operation cannot be finished in time).
            If you want to use ``await`` in the handler, please use ``asyncio.create_task`` to create a new coroutine.

        .. note::
            Currently, python-ndn does not handle PIT Tokens.
        """
        name = Name.normalize(name)

        def decorator(func: Route):
            self._autoreg_routes.append((name, func, validator, need_raw_packet, need_sig_ptrs))
            if self.face.running:
                aio.create_task(self.register(name, func, validator, need_raw_packet, need_sig_ptrs))
            return func
        return decorator

    async def register(self, name: NonStrictName, func: Optional[Route], validator: Optional[Validator] = None,
                       need_raw_packet: bool = False, need_sig_ptrs: bool = False) -> bool:
        """
        Register a route for a specific prefix dynamically.

        :param name: the Name prefix for this route.
        :type name: :any:`NonStrictName`
        :param func: the onInterest function for the specified route.
            If ``None``, the NDNApp will only send the register command to forwarder,
            without setting any callback function.
        :type func: Optional[Callable[[:any:`FormalName`, :any:`InterestParam`, Optional[:any:`BinaryStr`]], ``None``]]
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
        if func is not None:
            self.set_interest_filter(name, func, validator, need_raw_packet, need_sig_ptrs)

        # Fix the issue that NFD only allows one packet signed by a specific key for a timestamp number
        async with self._prefix_register_semaphore:
            try:
                _, _, reply = await self.express_interest(
                    name=make_command('rib', 'register', self.face, name=name),
                    lifetime=1000)
                ret = parse_response(reply)
                if ret['status_code'] != 200:
                    self.logger.error(f'Registration for {Name.to_str(name)} failed: '
                                      f'{ret["status_code"]} {ret["status_text"]}')
                    return False
                else:
                    self.logger.debug(f'Registration for {Name.to_str(name)} succeeded: '
                                      f'{ret["status_code"]} {ret["status_text"]}')
                    return True
            except (InterestNack, InterestTimeout, InterestCanceled, ValidationFailure) as e:
                self.logger.error(f'Registration for {Name.to_str(name)} failed: {e.__class__.__name__}')
                return False

    async def unregister(self, name: NonStrictName) -> bool:
        """
        Unregister a route for a specific prefix.

        :param name: the Name prefix.
        :type name: :any:`NonStrictName`
        """
        name = Name.normalize(name)
        del self._prefix_tree[name]
        try:
            await self.express_interest(make_command('rib', 'unregister', self.face, name=name), lifetime=1000)
            return True
        except (InterestNack, InterestTimeout, InterestCanceled, ValidationFailure):
            return False

    def set_interest_filter(self, name: NonStrictName, func: Route,
                            validator: Optional[Validator] = None, need_raw_packet: bool = False,
                            need_sig_ptrs: bool = False):
        """
        Set the callback function for an Interest prefix without sending a register command to the forwarder.

        .. note::
            All callbacks registered by ``set_interest_filter`` are removed when disconnected from
            the the forwarder, and will not be added back after reconnection.
            This behaviour is the same as ``register``.
            Therefore, it is strongly recommended to use ``route`` for static routes.
        """
        name = Name.normalize(name)
        node = self._prefix_tree.setdefault(name, PrefixTreeNode())
        if node.callback:
            raise ValueError(f'Duplicated registration: {Name.to_str(name)}')
        node.callback = func
        node.extra_param = {'raw_packet': need_raw_packet, 'sig_ptrs': need_sig_ptrs}
        if validator:
            node.validator = validator

    def unset_interest_filter(self, name: NonStrictName):
        """
        Remove the callback function for an Interest prefix without sending an unregister command.

        .. note::
            ``unregister`` will only remove the callback if the callback's name matches exactly
            the route's name.
            This is because there may be one route whose name is the prefix of another.
            To avoid cancelling unexpected routes, neither ``unregister`` nor ``unset_interest_filter``
            behaves in a cascading manner.
            Please remove callbacks manually.
        """
        name = Name.normalize(name)
        del self._prefix_tree[name]

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
            self.logger.warning('No route: %s' % name)
            return
        node = trie_step.value
        if node.callback is None:
            self.logger.warning('No callback: %s' % name)
            return
        if app_param is not None or sig.signature_info is not None:
            if not await params_sha256_checker(name, sig):
                self.logger.warning('Drop malformed Interest: %s' % name)
                return

        # In case the validator blocks the pipeline, create a task
        async def submit_interest():
            if sig.signature_info is not None:
                validator = node.validator if node.validator else self.int_validator
                valid = await validator(name, sig)
            else:
                valid = True
            if not valid:
                self.logger.warning('Drop unvalidated Interest: %s' % name)
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
        aio.create_task(submit_interest())
