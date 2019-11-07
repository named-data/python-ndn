import asyncio as aio
from ndn.app import NDNApp
from ndn.types import InterestNack, InterestTimeout, InterestCanceled, ValidationFailure, NetworkError
from ndn.encoding import Name, is_binary_str
from ndn.app_support.nfd_mgmt import GeneralStatus
import logging
import time


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.DEBUG,
                    style='{')


app = NDNApp()


def decode_dict(msg):
    ret = msg.asdict()
    for k, v in ret.items():
        if is_binary_str(v):
            ret[k] = bytes(v).decode()
        else:
            ret[k] = str(v)
    return ret


async def retry():
    while True:
        try:
            name = Name.from_str('/localhost/nfd/status/general')
            print(f'Sending Interest')
            data_name, meta_info, content = await app.express_interest(
                name, must_be_fresh=True, can_be_prefix=True, lifetime=60000)
            print(bytes(content) if content else None)
            msg = GeneralStatus.parse(content)
            status = decode_dict(msg)
            print(status)

        except InterestNack as e:
            print(f'Nacked with reason={e.reason}')
        except InterestTimeout:
            print(f'Timeout')
        except (InterestCanceled, NetworkError):
            print(f'Canceled')
            break
        except ValidationFailure:
            print(f'Data failed to validate')
        await aio.sleep(1.0)
    print('Finished run')


def main():
    running = True
    while running:
        print('Connecting')
        app_main = retry()
        try:
            running = app.run_forever(after_start=app_main)
        except (FileNotFoundError, ConnectionRefusedError):
            app_main.close()
        if running:
            time.sleep(1.0)


if __name__ == '__main__':
    main()
