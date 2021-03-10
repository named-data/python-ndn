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
