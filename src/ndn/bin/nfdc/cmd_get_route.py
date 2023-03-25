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
from ...app_support.nfd_mgmt import FibStatus, RibStatus
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('Get-Route', aliases=['route', 'gr'])
    parser.add_argument('route', metavar='ROUTE', nargs='?', default='',
                        help='The prefix of the specified route to query')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    app = NDNApp()
    route = args.route

    async def list_route():
        try:
            fib_data = await express_interest(app, "/localhost/nfd/fib/list")
            fib_msg = FibStatus.parse(fib_data)
            rib_data = await express_interest(app, "/localhost/nfd/rib/list")
            rib_msg = RibStatus.parse(rib_data)
            # TODO: Should calculate the length instead of using a fixed number
            print('Forwarding Table (FIB)')
            for ent in fib_msg.entries:
                prefix = Name.to_str(ent.name)
                if route and prefix != route:
                    continue
                print(prefix)
                for nh in ent.next_hop_records:
                    print(f'\tFaceID={nh.face_id:<5} Cost={nh.cost:<5}')
            print()
            print('Routing Table (RIB)')
            for ent in rib_msg.entries:
                prefix = Name.to_str(ent.name)
                if route and prefix != route:
                    continue
                print(prefix)
                for nh in ent.routes:
                    print(f'\tFaceID={nh.face_id:<5} Cost={nh.cost:<5} Origin={nh.origin:<3} Flags={nh.flags}')
        finally:
            app.shutdown()

    app.run_forever(list_route())
