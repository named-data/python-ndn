import logging
import sys
from ndn.app import NDNApp
from ndn.app_support.segment_fetcher import segment_fetcher


logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    level=logging.INFO,
                    style='{')
app = NDNApp()


async def main():
    cnt = 0
    async for seg in segment_fetcher(app, sys.argv[1]):
        print(bytes(seg).decode(), end='')
        cnt += 1
    print(f'\n{cnt} segments fetched.')
    app.shutdown()


if __name__ == '__main__':
    if len(sys.argv) <= 1:
        print(f'Usage: {sys.argv[0]} <name>')
        exit(0)
    app.run_forever(after_start=main())
