# -----------------------------------------------------------------------------
# Copyright (C) 2019-2021 The python-ndn authors
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
import argparse
from ...appv2 import NDNApp
from ...encoding import Name
from ...app_support.nfd_mgmt import StrategyChoiceMsg
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('Get-Strategy', aliases=['strategy', 'gs'])
    parser.add_argument('prefix', metavar='PREFIX', nargs='?', default='',
                        help='The specified route prefix')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    app = NDNApp()
    prefix = args.prefix

    async def list_strategy():
        try:
            data = await express_interest(app, "/localhost/nfd/strategy-choice/list")
            msg = StrategyChoiceMsg.parse(data)
            for s in msg.strategy_choices:
                s_prefix = Name.to_str(s.name)
                if prefix and s_prefix != prefix:
                    continue
                print(f'{s_prefix}\n\t{Name.to_str(s.strategy.name)}')
        finally:
            app.shutdown()

    app.run_forever(list_strategy())
