from ndn.app import NDNApp
from ndn.errors import InterestNack, InterestTimeout
from ndn.encoding import InterestParam
import asyncio as aio
import logging


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.DEBUG,
                        style='{')


app = NDNApp()


async def main1():
    while not app.face.running:
        print('sleeping...')
        await aio.sleep(0)

    try:
        print('expressing...')
        await app.express_interest("/ndn/not-exist",
                                   InterestParam(must_be_fresh=True, can_be_prefix=True, lifetime=1000))
    except InterestNack as e:
        print(f'Nacked with {e.reason}')
    except InterestTimeout:
        print(f'Timed out')
    finally:
        print('shutting down')
        app.shutdown()
    print('Finished')


if __name__ == '__main__':
    app.run_forever(after_start=main1())
