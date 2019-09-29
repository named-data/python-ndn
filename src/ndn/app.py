import struct
import logging
import asyncio as aio
from typing import Optional
from .encoding import BinaryStr, TypeNumber, LpTypeNumber, parse_interest, \
    parse_network_nack, parse_data, DecodeError, Name, NonStrictName, DataParam, \
    make_data, InterestParam, make_interest
from .security.keychain import KeyChain, make_digest_keychain
from .transport.stream_socket import Face, UnixFace


class NetworkError(Exception):
    pass


class NDNApp:
    face: Face = None
    keychain: KeyChain = None

    def __init__(self):
        self.face = UnixFace(self._receive)
        self.keychain = make_digest_keychain()

    async def _receive(self, typ: int, data: BinaryStr):
        logging.debug(f'Packet received {bytes(data)}')
        try:
            if typ == TypeNumber.INTEREST:
                name, param, app_param, sig = parse_interest(data, with_tl=False)
                logging.info(f'Interest received {Name.to_str(name)}')
                pass
            elif typ == TypeNumber.DATA:
                name, param, content, sig = parse_data(data, with_tl=False)
                logging.info(f'Data received {Name.to_str(name)}')
                pass
            elif typ == LpTypeNumber.LP_PACKET:
                nack_reason, interest = parse_network_nack(data, with_tl=False)
                name, _, _, _ = parse_interest(interest, with_tl=True)
                logging.info(f'NetworkNack received {Name.to_str(name)}, reason={nack_reason}')
                pass
        except (DecodeError, TypeError, ValueError, struct.error):
            logging.warning(f'Unable to decode received packet')

    def put_raw_packet(self, data: BinaryStr):
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        self.face.send(data)

    def put_data(self,
                 name: NonStrictName,
                 data_param: DataParam,
                 content: Optional[BinaryStr] = None,
                 **kwargs):
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        signer = self.keychain(kwargs)
        data = make_data(name, data_param, content, signer=signer, **kwargs)
        self.face.send(data)

    async def express_interest(self,
                               name: NonStrictName,
                               interest_param: InterestParam,
                               app_param: Optional[BinaryStr] = None,
                               **kwargs):
        if not self.face.running:
            raise NetworkError('cannot send packet before connected')
        if app_param is not None:
            signer = self.keychain(kwargs)
        else:
            signer = None
        interest, final_name = make_interest(name, interest_param, app_param,
                                             signer=signer, need_final_name=True, **kwargs)
        pass

    async def main_loop(self):
        await self.face.open()
        logging.debug('Connected to NFD node, start running...')
        await self.face.run()

    def shutdown(self):
        self.face.shutdown()

    def run_forever(self):
        task = self.main_loop()
        try:
            aio.get_event_loop().run_until_complete(task)
        except KeyboardInterrupt:
            logging.info('Receiving Ctrl+C, shutdown')
        finally:
            self.shutdown()

    def route(self):
        pass

    def register_prefix(self):
        pass

    def set_filter(self):
        pass

    def unregister(self):
        pass
