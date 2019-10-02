import struct
import logging
import asyncio as aio
from typing import Optional, Any, Awaitable, Coroutine, Tuple
from .encoding import BinaryStr, TypeNumber, LpTypeNumber, parse_interest, \
    parse_network_nack, parse_data, DecodeError, Name, NonStrictName, MetaInfo, \
    make_data, InterestParam, make_interest, FormalName, SignaturePtrs
from .security.keychain import KeyChain, make_digest_keychain
from .security.validator import Validator
from .security.digest_validator import DigestValidator
from .transport.stream_socket import Face, UnixFace
from .name_tree import NameTrie, NameTreeNode
from .errors import NetworkError, InterestTimeout


class NDNApp:
    face: Face = None
    keychain: KeyChain = None
    name_tree: NameTrie = None
    validator: Validator = None

    def __init__(self):
        self.face = UnixFace(self._receive)
        self.keychain = make_digest_keychain()
        self.name_tree = NameTrie()
        self.validator = DigestValidator()

    async def _receive(self, typ: int, data: BinaryStr):
        logging.debug('Packet received %s, %s' % (typ, bytes(data)))
        try:
            if typ == TypeNumber.INTEREST:
                try:
                    name, param, app_param, sig = parse_interest(data, with_tl=False)
                except (DecodeError, TypeError, ValueError, struct.error):
                    raise DecodeError
                logging.info('Interest received %s' % Name.to_str(name))
                await self._on_interest(name, param, app_param, sig)
            elif typ == TypeNumber.DATA:
                try:
                    name, meta_info, content, sig = parse_data(data, with_tl=False)
                except (DecodeError, TypeError, ValueError, struct.error):
                    raise DecodeError
                logging.info('Data received %s' % Name.to_str(name))
                await self._on_data(name, meta_info, content, sig)
            elif typ == LpTypeNumber.LP_PACKET:
                try:
                    nack_reason, interest = parse_network_nack(data, with_tl=False)
                    name, _, _, _ = parse_interest(interest, with_tl=True)
                except (DecodeError, TypeError, ValueError, struct.error):
                    raise DecodeError
                logging.info('NetworkNack received %s, reason=%s' % (Name.to_str(name), nack_reason))
                self._on_nack(name, nack_reason)
        except DecodeError:
            logging.warning('Unable to decode received packet')

    def put_raw_packet(self, data: BinaryStr):
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        self.face.send(data)

    def put_data(self,
                 name: NonStrictName,
                 meta_info: Optional[MetaInfo] = None,
                 content: Optional[BinaryStr] = None,
                 **kwargs):
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        signer = self.keychain(kwargs)
        if meta_info is None:
            meta_info = MetaInfo.from_dict(kwargs)
        data = make_data(name, meta_info, content, signer=signer, **kwargs)
        self.face.send(data)

    def express_interest(self,
                         name: NonStrictName,
                         interest_param: Optional[InterestParam] = None,
                         app_param: Optional[BinaryStr] = None,
                         **kwargs) -> Coroutine[Any, None, Tuple[FormalName, MetaInfo, Optional[BinaryStr]]]:
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        if app_param is not None:
            signer = self.keychain(kwargs)
        else:
            signer = None
        if interest_param is None:
            interest_param = InterestParam.from_dict(kwargs)
        interest, final_name = make_interest(name, interest_param, app_param,
                                             signer=signer, need_final_name=True, **kwargs)
        future = aio.get_event_loop().create_future()
        node = self.name_tree.setdefault(final_name, NameTreeNode())
        node.append_interest(future, interest_param)
        self.face.send(interest)
        return self._wait_for_data(future, interest_param.lifetime, final_name, node)

    async def _wait_for_data(self, future: aio.Future, lifetime: int, name: FormalName, node: NameTreeNode):
        lifetime = 100 if lifetime is None else lifetime
        try:
            data = await aio.wait_for(future, timeout=lifetime/1000.0)
        except aio.TimeoutError:
            if node.timeout(future):
                del self.name_tree[name]
            raise InterestTimeout()
        return data

    async def main_loop(self, after_start: Awaitable = None):
        await self.face.open()
        if after_start:
            aio.get_event_loop().create_task(after_start)
        logging.debug('Connected to NFD node, start running...')
        await self.face.run()

    def shutdown(self):
        print('Manually shutdown')
        self.face.shutdown()

    def run_forever(self, after_start: Awaitable = None):
        task = self.main_loop(after_start)
        try:
            aio.get_event_loop().run_until_complete(task)
        except KeyboardInterrupt:
            logging.info('Receiving Ctrl+C, shutdown')
        finally:
            self.face.shutdown()
        logging.debug('Face is down now')

    def route(self):
        pass

    def register(self):
        pass

    def unregister(self):
        pass

    def _on_nack(self, name: FormalName, nack_reason: int):
        node = self.name_tree[name]
        if node:
            if node.nack_interest(nack_reason):
                del self.name_tree[name]

    async def _on_data(self, name: FormalName, meta_info: MetaInfo,
                       content: Optional[BinaryStr], sig: SignaturePtrs):
        valid = await self.validator.data_validate(name, sig)
        clean_list = []
        for prefix, node in self.name_tree.prefixes(name):
            if valid:
                clean = node.satisfy(name, meta_info, content)
            else:
                clean = node.invalid(name, meta_info, content)
            if clean:
                clean_list.append(prefix)
        for prefix in clean_list:
            del self.name_tree[prefix]

    async def _on_interest(self, name: FormalName, param: InterestParam,
                           app_param: Optional[BinaryStr], sig: SignaturePtrs):
        valid = await self.validator.interest_validate(name, sig)
        if not valid:
            return
        pass
