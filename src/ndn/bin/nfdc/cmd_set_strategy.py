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
from ...app_support.nfd_mgmt import parse_response, make_command_v2
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('Set-Strategy', aliases=['ss'])
    parser.add_argument('prefix', metavar='PREFIX',
                        help='The prefix of the specified strategy choice to remove')
    parser.add_argument('strategy', metavar='STRATEGY',
                        help='The name of strategy. Can be [multicast, best-route, access, asf, self-learning, ncc]'
                             ' or the full name of any supported strategy')
    parser.set_defaults(executor=execute)


STRATEGY_FULLNAME = {
    'multicast': '/localhost/nfd/strategy/multicast',
    'best-route': '/localhost/nfd/strategy/best-route',
    'access': '/localhost/nfd/strategy/access',
    'asf': '/localhost/nfd/strategy/asf',
    'self-learning': '/localhost/nfd/strategy/self-learning',
    'ncc': '/localhost/nfd/strategy/ncc',
}


def execute(args: argparse.Namespace):
    app = NDNApp()
    prefix = args.prefix
    strategy = args.strategy
    if strategy in STRATEGY_FULLNAME:
        strategy = STRATEGY_FULLNAME[strategy]

    async def remove_strategy():
        try:
            cmd = make_command_v2('strategy-choice', 'set', name=prefix, strategy=strategy)
            res = await express_interest(app, cmd)
            msg = parse_response(res)
            print(f'{msg["status_code"]} {msg["status_text"]}')
        finally:
            app.shutdown()

    app.run_forever(after_start=remove_strategy())
