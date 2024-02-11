# -----------------------------------------------------------------------------
# Copyright (C) 2019-2022 The python-ndn authors
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
import asyncio as aio
import typing
import struct
import logging
from hashlib import sha256
from dataclasses import dataclass
from .transport.face import Face
from .transport.prefix_registerer import PrefixRegisterer
from . import security as sec
from . import encoding as enc
from . import name_tree
from . import types
from . import utils
from .encoding import ndnlp_v2 as ndnlp
from .client_conf import read_client_conf, default_face, default_keychain, default_registerer


DEFAULT_LIFETIME = 4000

ValidResult = types.ValidResult

PktContext = dict[str, any]
r"""The context for NDN Interest or Data handling."""

ReplyFunc = typing.Callable[[enc.BinaryStr], bool]
r"""
Continuation function for :any:`IntHandler` to respond to an Interest.

..  function:: (data: BinaryStr) -> bool

    :param data: an encoded Data packet.
    :type data: :any:`BinaryStr`
    :return: True for success, False upon error.
"""

IntHandler = typing.Callable[[enc.FormalName, typing.Optional[enc.BinaryStr], ReplyFunc, PktContext], None]
r"""
Interest handler function associated with a name prefix.

The function should use the provided ``reply`` callback to reply with Data, which can handle PIT
token properly.

..  function:: (name: FormalName, app_param: Optional[BinaryStr], reply: ReplyFunc, context: PktContext) -> None

    :param name: Interest name.
    :type name: :any:`FormalName`
    :param app_param: Interest ApplicationParameters value, or None if absent.
    :type app_param: Optional[:any:`BinaryStr`]
    :param reply: continuation function to respond with Data.
    :type reply: :any:`ReplyFunc`
    :param context: packet handler context.
    :type context: :any:`PktContext`

.. note::
    Interest handler function must be a normal function instead of an ``async`` one.
    This is on purpose, because an Interest is supposed to be replied ASAP,
    even it cannot finish the request in time.
    To provide some feedback, a better practice is replying with an Application NACK
    (or some equivalent Data packet saying the operation cannot be finished in time).
    If you want to use ``await`` in the handler, please use ``asyncio.create_task`` to create a new coroutine.
"""

Validator = typing.Callable[[enc.FormalName, enc.SignaturePtrs, PktContext],
                            typing.Coroutine[any, None, ValidResult]]
r"""
Validator function that validates Interest or Data signature against trust policy.

..  function:: (name: FormalName, sig: SignaturePtrs, context: PktContext) -> Coroutine[ValidResult]

    :param name: Interest or Data name.
    :type name: :any:`FormalName`
    :param sig: packet signature pointers.
    :type sig: :any:`SignaturePtrs`
    :param context: packet handler context.
    :type context: :any:`PktContext`
"""


async def pass_all(_name, _sig, _context):
    return types.ValidResult.PASS


@dataclass
class PrefixTreeNode:
    callback: IntHandler = None
    validator: typing.Optional[Validator] = None


@dataclass
class PendingIntEntry:
    future: aio.Future
    deadline: int
    can_be_prefix: bool
    must_be_fresh: bool
    validator: Validator
    implicit_sha256: enc.BinaryStr = b''
    task: typing.Optional[aio.Task] = None

    async def satisfy(self, data: types.DataTuple):
        name, meta_info, content, sig, raw_packet = data
        pkt_context = {
            'meta_info': meta_info,
            'sig_ptrs': sig,
            'raw_packet': raw_packet,
            'deadline': self.deadline,
        }
        if self.validator is not None:
            try:
                valid = await self.validator(name, sig, pkt_context)
            except (aio.CancelledError, aio.TimeoutError):
                valid = ValidResult.TIMEOUT
        else:
            valid = ValidResult.FAIL
        if self.future.cancelled() or self.future.done():
            # Don't know why but there was a race condition with timeout()
            # The sequence was: Interest sent -> Data arrived -> timeout() -> satisfy()
            # Cannot reproduce the scenario. Especially, delay in validator() does not trigger the race condition
            # But anyway, let me add a guard check here.
            return
        if valid == ValidResult.PASS or valid == ValidResult.ALLOW_BYPASS:
            self.future.set_result((name, content, pkt_context))
        else:
            self.future.set_exception(types.ValidationFailure(name, meta_info, content, sig, valid))


class InterestTreeNode:
    pending_list: list[PendingIntEntry]

    def __init__(self):
        self.pending_list = []

    def append_interest(self, future: aio.Future, deadline: int, param: enc.InterestParam,
                        validator: Validator, implicit_sha256: enc.BinaryStr):
        self.pending_list.append(
            PendingIntEntry(future, deadline, param.can_be_prefix, param.must_be_fresh, validator, implicit_sha256))

    def nack_interest(self, nack_reason: int) -> bool:
        for entry in self.pending_list:
            entry.future.set_exception(types.InterestNack(nack_reason))
        return True

    def satisfy(self, data: types.DataTuple, is_prefix: bool) -> bool:
        unsatisfied_entries = []
        raw_packet = data[4]
        for entry in self.pending_list:
            if entry.can_be_prefix or not is_prefix:
                if len(entry.implicit_sha256) > 0:
                    data_sha256 = sha256(raw_packet).digest()
                    passed = data_sha256 == entry.implicit_sha256
                else:
                    passed = True
            else:
                passed = False
            if passed:
                # Try to validate the packet
                aio.create_task(entry.satisfy(data))
            else:
                unsatisfied_entries.append(entry)
        if unsatisfied_entries:
            self.pending_list = unsatisfied_entries
            return False
        else:
            return True

    def timeout(self, future: aio.Future):
        # Exception is raised by outside code.
        for ele in self.pending_list:
            if ele.future is future and ele.task is not None:
                ele.task.cancel()
        self.pending_list = [ele for ele in self.pending_list if ele.future is not future]
        return not self.pending_list

    def cancel(self):
        for entry in self.pending_list:
            entry.future.cancel()
            if entry.task is not None:
                entry.task.cancel()


class NDNApp:
    """
    An NDN application.
    """
    # PIT and FIB here are not real PIT/FIB, but a data structure that handles expressed Interests (for PIT)
    # and registered handlers & routes (for FIB). Since they share the functionality with real PIT and FIB,
    # I borrow the word to have a shorter variable name.
    _pit: name_tree.NameTrie = None
    _fib: name_tree.NameTrie = None
    face: Face = None
    registerer: PrefixRegisterer = None
    _autoreg_routes: list[enc.FormalName]
    logger: logging.Logger

    def __init__(self, face=None, client_conf=None, registerer=None):
        self.logger = logging.getLogger(__name__)
        config = client_conf if client_conf else {}
        if not face:
            if 'transport' not in config:
                config = read_client_conf() | config
        if face is not None:
            self.face = face
        else:
            self.face = default_face(config['transport'])
        if registerer is not None:
            self.registerer = registerer
        else:
            self.registerer = default_registerer()
        self.registerer.set_app(app=self)
        self.face.callback = self._receive
        self._pit = name_tree.NameTrie()
        self._fib = name_tree.NameTrie()
        self._autoreg_routes = []

    @staticmethod
    def default_keychain(client_conf=None) -> sec.Keychain:
        if not client_conf:
            config = read_client_conf()
        else:
            config = read_client_conf() | client_conf
        return default_keychain(config['pib'], config['tpm'])

    async def _receive(self, typ: int, data: enc.BinaryStr):
        """
        Pipeline when a packet is received.

        :param typ: the Type.
        :param data: the Value of the packet with TL.
        """
        # if self.logger.isEnabledFor(logging.DEBUG):
        #     self.logger.debug('Packet received %s, %s' % (typ, bytes(data)))
        if typ == enc.LpTypeNumber.LP_PACKET:
            try:
                lp_pkt = enc.parse_lp_packet_v2(data, with_tl=True)
            except (enc.DecodeError, TypeError, ValueError, struct.error):
                self.logger.warning('Unable to decode received packet')
                return
            if lp_pkt.nack is not None:
                nack_reason = lp_pkt.nack.nack_reason
            else:
                nack_reason = None
            pit_token = lp_pkt.pit_token
            data = lp_pkt.fragment
            typ, _ = enc.parse_tl_num(data)
        else:
            nack_reason = None
            pit_token = None

        if nack_reason is not None:
            try:
                name, _, _, _ = enc.parse_interest(data, with_tl=True)
            except (enc.DecodeError, TypeError, ValueError, struct.error):
                self.logger.warning('Unable to decode the fragment of LpPacket')
                return
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug('NetworkNack received %s, reason=%s' % (enc.Name.to_str(name), nack_reason))
            self._on_nack(name, nack_reason)
        else:
            if typ == enc.TypeNumber.INTEREST:
                try:
                    name, param, app_param, sig = enc.parse_interest(data, with_tl=True)
                except (enc.DecodeError, TypeError, ValueError, struct.error):
                    self.logger.warning('Unable to decode received packet')
                    return
                if self.logger.isEnabledFor(logging.DEBUG):
                    if pit_token:
                        self.logger.debug(
                            f'Interest received {enc.Name.to_str(name)} w/ token={bytes(pit_token).hex()}')
                    else:
                        self.logger.debug(f'Interest received {enc.Name.to_str(name)}')
                await self._on_interest(name, pit_token, param, app_param, sig, raw_packet=data)
            elif typ == enc.TypeNumber.DATA:
                try:
                    name, meta_info, content, sig = enc.parse_data(data, with_tl=True)
                except (enc.DecodeError, TypeError, ValueError, struct.error):
                    self.logger.warning('Unable to decode received packet')
                    return
                if self.logger.isEnabledFor(logging.DEBUG):
                    self.logger.debug(f'Data received {enc.Name.to_str(name)}')
                await self._on_data(name, meta_info, content, sig, raw_packet=data)
            else:
                self.logger.warning('Unable to decode received packet')

    @staticmethod
    def make_data(name: enc.NonStrictName, content: typing.Optional[enc.BinaryStr],
                  signer: typing.Optional[enc.Signer], **kwargs):
        r"""
        Encode a data packet without requiring an NDNApp instance.
        This is simply a wrapper of encoding.make_data.
        I write this because most people seem not aware of the ``make_data`` function in the encoding package.
        The corresponding ``make_interest`` is less useful (one should not reuse nonce) and thus not wrapped.
        Sync protocol should use encoding.make_interest if necessary.
        Also, since having a default signer encourages bad habit,
        prepare_data is removed except for command Interests sent to NFD.
        Please call ``keychain.get_signer({})`` to use the default certificate.

        :param name: the Name.
        :type name: :any:`NonStrictName`
        :param content: the Content.
        :type content: Optional[:any:`BinaryStr`]
        :param signer: the Signer used to sign the packet.
        :type signer: Optional[:any:`Signer`]
        :param kwargs: arguments for :any:`MetaInfo`.
        :return: TLV encoded Data packet.
        """
        if 'meta_info' in kwargs:
            meta_info = kwargs['meta_info']
        else:
            meta_info = enc.MetaInfo.from_dict(kwargs)
        return enc.make_data(name, meta_info, content, signer=signer)

    async def _on_interest(self, name: enc.FormalName, pit_token: typing.Optional[enc.BinaryStr],
                           param: enc.InterestParam, app_param: typing.Optional[enc.BinaryStr], sig: enc.SignaturePtrs,
                           raw_packet: enc.BinaryStr):
        trie_step = self._fib.longest_prefix(name)
        if not trie_step:
            self.logger.warning('No route: %s' % name)
            return
        node: PrefixTreeNode = trie_step.value
        if node.callback is None:
            self.logger.warning('No callback: %s' % name)
            return
        sig_required = app_param is not None or sig.signature_info is not None
        if sig_required:
            if not await sec.params_sha256_checker(name, sig):
                self.logger.warning('Drop malformed Interest: %s' % name)
                return

        # Use context to handle misc parameters
        if param.lifetime is not None:
            deadline = utils.timestamp() + param.lifetime
        else:
            deadline = utils.timestamp() + DEFAULT_LIFETIME
        context = {
            'int_param': param,
            'pit_token': pit_token,
            'sig_ptrs': sig,
            'raw_packet': raw_packet,
            'deadline': deadline,
        }

        def reply(data: enc.BinaryStr) -> bool:
            now = utils.timestamp()
            if now > deadline:
                self.logger.warning(f'Deadline passed, unable to reply to {enc.Name.to_str(name)}')
                return False
            if pit_token is None:
                self._put_raw_packet(data)
            else:
                self._put_raw_packet_with_pit_token(data, pit_token)

        # In case the validator blocks the pipeline, create a task
        async def submit_interest():
            if sig_required:
                # In v2, to enforce security, validator is required. Also, all interests with app_param are checked.
                # The validator needs to manually pass it if the application wants to handle unsigned Interests with
                # app_param.
                if node.validator is not None:
                    valid = await node.validator(name, sig, context)
                else:
                    valid = ValidResult.FAIL
            else:
                valid = ValidResult.PASS
            if valid == ValidResult.PASS or valid == ValidResult.ALLOW_BYPASS:
                node.callback(name, app_param, reply, context)
            else:
                self.logger.warning('Drop unvalidated Interest: %s' % name)
                return
        aio.create_task(submit_interest())

    def _put_raw_packet(self, data: enc.BinaryStr):
        r"""
        Send a raw Data packet.

        :param data: TLV encoded Data packet.
        :type data: :any:`BinaryStr`
        :raises NetworkError: the face to NFD is down.
        """
        if not self.face.running:
            raise types.NetworkError('cannot send packet before connected')
        self.face.send(data)

    def _put_raw_packet_with_pit_token(self, data: enc.BinaryStr, pit_token: enc.BinaryStr):
        r"""
        Wrap a raw Data packet with PIT Token and send.
        Used to reply an Interest with PIT Token provided.

        :param data: TLV encoded Data packet.
        :type data: :any:`BinaryStr`
        :param pit_token: The PIT Token provided.
        :type pit_token: :any:`BinaryStr`
        :raises NetworkError: the face to NFD is down.
        """
        if not self.face.running:
            raise types.NetworkError('cannot send packet before connected')
        pkt = ndnlp.LpPacket()
        pkt.lp_packet = ndnlp.LpPacketValue()
        pkt.lp_packet.pit_token = pit_token
        pkt.lp_packet.fragment = data
        wire = pkt.encode()
        self.face.send(wire)

    def _put_raw_packet_with_pit_token_nocopy(self, data: enc.BinaryStr, pit_token: enc.BinaryStr):
        r"""
        Wrap a raw Data packet with PIT Token and send.
        Used to reply an Interest with PIT Token provided.

        This function is reserved as a backup because it assumes the face to be stream face.

        :param data: TLV encoded Data packet.
        :type data: :any:`BinaryStr`
        :param pit_token: The PIT Token provided.
        :type pit_token: :any:`BinaryStr`
        :raises NetworkError: the face to NFD is down.
        """
        # To avoid extra copy, we manually encode the header and send it separately from Data body
        # The format is: LP-T LP-L (PIT-TOKEN-TLV) FRAG-T FRAG-L
        if not self.face.running:
            raise types.NetworkError('cannot send packet before connected')
        pt = ndnlp.LpPacketValue()
        pt.pit_token = pit_token
        pt_wire = pt.encode()
        frag_l = len(data)
        lp_l = len(pt_wire) + enc.get_tl_num_size(ndnlp.LpTypeNumber.FRAGMENT) + enc.get_tl_num_size(frag_l)
        wire_l = enc.get_tl_num_size(ndnlp.LpTypeNumber.LP_PACKET) + enc.get_tl_num_size(lp_l) + lp_l
        wire = bytearray(wire_l)
        pos = 0
        pos += enc.write_tl_num(ndnlp.LpTypeNumber.LP_PACKET, wire, pos)
        pos += enc.write_tl_num(lp_l, wire, pos)
        wire[pos:pos+len(pt_wire)] = pt_wire
        pos += len(pt_wire)
        pos += enc.write_tl_num(ndnlp.LpTypeNumber.FRAGMENT, wire, pos)
        pos += enc.write_tl_num(frag_l, wire, pos)
        self.face.send(wire)
        self.face.send(data)

    def attach_handler(self, name: enc.NonStrictName, handler: IntHandler,
                       validator: typing.Optional[Validator] = None):
        """
        Attach an Interest handler at a name prefix.
        Incoming Interests under the specified name prefix will be dispatched to the handler.

        This only sets the handler within NDNApp, but does not send prefix registration commands
        to the forwarder.
        To register the prefix in the forwarder, use :any:`register`.
        The handler association is retained even if the forwarder is disconnected.

        :param name: name prefix.
        :type name: :any:`NonStrictName`
        :param handler: Interest handler function.
        :type handler: :any:`IntHandler`
        :param validator: validator for signed Interests.
            Non signed Interests, i.e. those without ApplicationParameters and SignatureInfo, are
            passed to the handler directly without calling the validator.
            Interests with malformed ParametersSha256DigestComponent are dropped silently.
            If a validator is not provided (set to ``None``), signed Interests will be dropped.
            Otherwise, signed Interests are passed to the validator.
            Those failing the validation are dropped silently.
            Those passing the validation are passed to the handler function.
        :type validator: Optional[:any:`Validator`]
        """
        name = enc.Name.normalize(name)
        node = self._fib.setdefault(name, PrefixTreeNode())
        if node.callback:
            raise ValueError(f'Duplicated handler attachment: {enc.Name.to_str(name)}')
        node.callback = handler
        node.validator = validator

    def detach_handler(self, name: enc.NonStrictName):
        """
        Detach an Interest handler at a name prefix.

        This only deletes the handler within NDNApp, but does not unregister the prefix in the
        forwarder.
        To unregister the prefix in the forwarder, use :any:`unregister`.

        :param name: name prefix. This must exactly match the name passed to :any:`attach_handler`.
                     If there are Interest handlers attached to longer prefixes, each handler must
                     be removed explicitly.
        :type name: :any:`NonStrictName`
        """
        del self._fib[enc.Name.normalize(name)]

    async def register(self, name: enc.NonStrictName) -> bool:
        """
        Register a prefix in the forwarder.

        This only sends the prefix registration command to the forwarder.
        In order to receive incoming Interests, you also need to use :any:`attach_handler` to
        attach an Interest handler function.

        :param name: name prefix.
        :type name: :any:`NonStrictName`

        :raises ValueError: the prefix is already registered.
        :raises NetworkError: the face to NFD is down now.
        """
        name = enc.Name.normalize(name)
        return await self.registerer.register(name)

    async def unregister(self, name: enc.NonStrictName) -> bool:
        """
        Unregister a prefix in the forwarder.

        :param name: name prefix.
        :type name: :any:`NonStrictName`
        """
        name = enc.Name.normalize(name)
        return await self.registerer.unregister(name)

    def express_raw_interest(self,
                             final_name: enc.NonStrictName,
                             interest_param: enc.InterestParam,
                             raw_interest: enc.BinaryStr,
                             validator: Validator,
                             no_response: bool = False
                             ) -> typing.Coroutine[any, None,
                                                   tuple[enc.FormalName, typing.Optional[enc.BinaryStr], PktContext]]:
        if no_response:
            self.face.send(raw_interest)
            return None
        if validator is None:
            raise ValueError('Data Validator must not be None when expressing an Interest.')
        final_name = enc.Name.normalize(final_name)
        future = aio.get_running_loop().create_future()
        # Handle implicit SHA256
        if enc.Component.get_type(final_name[-1]) == enc.Component.TYPE_IMPLICIT_SHA256:
            node_name = final_name[:-1]
            implicit_sha256 = enc.Component.get_value(final_name[-1])
        else:
            node_name = final_name
            implicit_sha256 = b''
        node: InterestTreeNode = self._pit.setdefault(node_name, InterestTreeNode())
        deadline = utils.timestamp()
        if interest_param.lifetime is not None:
            deadline += interest_param.lifetime
        else:
            deadline += DEFAULT_LIFETIME
        node.append_interest(future, deadline, interest_param, validator, implicit_sha256)
        self.face.send(raw_interest)
        return self._wait_for_data(future, deadline, node_name, node)

    async def _wait_for_data(self, future: aio.Future, deadline: int, node_name: enc.FormalName,
                             node: InterestTreeNode):
        lifetime = deadline - utils.timestamp()
        if lifetime <= 0:
            # This happens if the application sends an Interest, does some calculation, and then fetches the result.
            # The Interest should be satisfied now. Thus, it should not be considered as an error.
            lifetime = 100
        try:
            data_name, content, pkt_context = await aio.wait_for(future, timeout=lifetime/1000.0)
        except aio.TimeoutError:
            if node.timeout(future):
                del self._pit[node_name]
            raise types.InterestTimeout()
        except aio.CancelledError:
            raise types.InterestCanceled()
        # ValidationError, InterestNack are passed to the parent caller
        return data_name, content, pkt_context

    async def _on_data(self, name: enc.FormalName, meta_info: enc.MetaInfo,
                       content: typing.Optional[enc.BinaryStr], sig: enc.SignaturePtrs,
                       raw_packet: enc.BinaryStr):
        clean_list = []
        for prefix, node in self._pit.prefixes(name):
            if node.satisfy((name, meta_info, content, sig, raw_packet), prefix != name):
                clean_list.append(prefix)
        for prefix in clean_list:
            del self._pit[prefix]

    def _on_nack(self, name: enc.FormalName, nack_reason: int):
        try:
            node = self._pit[name]
        except KeyError:
            node = None
        if node:
            if node.nack_interest(nack_reason):
                del self._pit[name]

    def express(self, name: enc.NonStrictName, validator: Validator,
                app_param: typing.Optional[enc.BinaryStr] = None,
                signer: typing.Optional[enc.Signer] = None,
                **kwargs) -> typing.Coroutine[any, None,
                                              tuple[enc.FormalName, typing.Optional[enc.BinaryStr], PktContext]]:
        r"""
        Express an Interest.

        The Interest packet is sent immediately and a coroutine used to get the result is returned.
        Awaiting on the returned coroutine will block until the Data is received.
        It then returns the Data name, Data Content value, and :any:`PktContext`.
        An exception is raised if NDNApp is unable to retrieve the Data.

        :param name: Interest name.
        :type name: :any:`NonStrictName`
        :param validator: validator for the retrieved Data packet.
        :type validator: :any:`Validator`
        :param app_param: Interest ApplicationParameters value. If this is not None, a signed
                          Interest is sent. NDNApp does not support sending parameterized
                          Interests that are not signed.
        :type app_param: Optional[:any:`BinaryStr`]
        :param signer: Signer for Interest signing. This is required if `app_param` is specified.
        :type signer: Optional[:any:`Signer`]
        :param kwargs: arguments for :any:`InterestParam`.
        :return: A tuple of (Name, Content, PacketContext) after ``await``.
        :rtype: Coroutine[Any, None, Tuple[:any:`FormalName`, Optional[:any:`BinaryStr`], :any:`PktContext`]]

        The following exceptions may be raised by ``express``:

        :raises NetworkError: the face to NFD is down before sending this Interest.
        :raises ValueError: when the signer is missing but app_param presents.

        The following exceptions may be raised by the returned coroutine:

        :raises InterestNack: an NetworkNack is received.
        :raises InterestTimeout: time out.
        :raises ValidationFailure: unable to validate the Data packet.
        :raises InterestCanceled: the face to NFD is shut down after sending this Interest.
        """
        if not self.face.running:
            raise types.NetworkError('cannot send packet before connected')
        if app_param is not None and signer is None:
            raise ValueError('An Interest with AppParam is required to be signed.')
        if 'interest_param' in kwargs:
            interest_param = kwargs['interest_param']
        else:
            if 'nonce' not in kwargs:
                kwargs['nonce'] = utils.gen_nonce()
            interest_param = enc.InterestParam.from_dict(kwargs)
        interest, final_name = enc.make_interest(name, interest_param, app_param, signer=signer, need_final_name=True)
        no_response = kwargs.get('no_response', False)
        return self.express_raw_interest(final_name, interest_param, interest, validator, no_response)

    def route(self, name: enc.NonStrictName, validator: typing.Optional[Validator] = None):
        r"""
        A decorator used to register a permanent route for a specific prefix.
        The decorated function should be an :any:`IntHandler`.

        This function is non-blocking and can be called at any time.
        It can be called before connecting to the forwarder.
        Every time a forwarder connection is established, NDNApp will automatically send
        prefix registration commands.
        Errors in prefix registration are ignored.

        :param name: name prefix.
        :type name: :any:`NonStrictName`
        :param validator: validator for signed Interests. See :any:`attach_handler` for details.
        :type validator: Optional[:any:`Validator`]

        :examples:
            .. code-block:: python3

                app = NDNApp()

                @app.route('/example/rpc')
                def on_interest(name, app_param, reply, context):
                    pass

        """
        name = enc.Name.normalize(name)

        def decorator(func: IntHandler):
            self._autoreg_routes.append(name)
            self.attach_handler(name, func, validator)
            if self.face.running:
                aio.create_task(self.register(name))
            return func
        return decorator

    def _clean_up(self):
        for node in self._pit.itervalues():
            node.cancel()
        # FIB is not cleared now
        self._pit.clear()

    def shutdown(self):
        """
        Manually shutdown the face to NFD.
        """
        self.logger.info('Manually shutdown')
        self.face.shutdown()

    async def main_loop(self, after_start: typing.Awaitable = None) -> bool:
        """
        The main loop of NDNApp.

        :param after_start: the coroutine to start after connection to NFD is established.
        :return: ``True`` if the connection is shutdown not by ``Ctrl+C``.
            For example, manually or by the other side.
        """
        async def starting_task():
            for name in self._autoreg_routes:
                await self.register(name)
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
                if isinstance(after_start, typing.Coroutine):
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

    def run_forever(self, after_start: typing.Awaitable = None):
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
