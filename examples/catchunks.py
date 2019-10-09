# -----------------------------------------------------------------------------
# Copyright (C) 2019 Xinyu Ma
#
# This file is part of python-ndn.
#
# python-ndn is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# python-ndn is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with python-ndn.  If not, see <https://www.gnu.org/licenses/>.
# -----------------------------------------------------------------------------
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
