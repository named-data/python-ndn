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
    parser = subparsers.add_parser('Remove-Strategy', aliases=['rs'])
    parser.add_argument('prefix', metavar='PREFIX',
                        help='The prefix of the specified strategy choice to remove')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    app = NDNApp()
    prefix = args.prefix

    async def remove_strategy():
        try:
            cmd = make_command_v2('strategy-choice', 'unset', name=prefix)
            res = await express_interest(app, cmd)
            msg = parse_response(res)
            print(f'{msg["status_code"]} {msg["status_text"]}')
        finally:
            app.shutdown()

    app.run_forever(after_start=remove_strategy())
