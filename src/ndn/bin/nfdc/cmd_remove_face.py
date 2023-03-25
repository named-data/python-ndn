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
from ...encoding import Name, Component
from ...app_support.nfd_mgmt import FaceStatusMsg, FaceQueryFilter, FaceQueryFilterValue, parse_response, \
    make_command_v2
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('Remove-Face', aliases=['rf'])
    parser.add_argument('face', metavar='FACE',
                        help='FaceID or URI of specified face')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    app = NDNApp()
    face = args.face

    async def remove_face(fid):
        print(f'Removing face {fid} ...', end='')
        cmd = make_command_v2('faces', 'destroy', face_id=fid)
        res = await express_interest(app, cmd)
        msg = parse_response(res)
        print(f'\t{msg["status_code"]} {msg["status_text"]}')

    async def run_with_fid(fid):
        try:
            await remove_face(fid)
        finally:
            app.shutdown()

    async def run_with_uri(uri):
        async def try_remove():
            data = await express_interest(app, data_name)
            if not data:
                return False
            elif data[0] == 0x65:
                msg = parse_response(data)
                print('Query failed with response', msg['status_code'], msg['status_text'])
            else:
                msg = FaceStatusMsg.parse(data)
                for f in msg.face_status:
                    await remove_face(f.face_id)
            return True

        try:
            name = "/localhost/nfd/faces/query"
            filt = FaceQueryFilter()
            filt.face_query_filter = FaceQueryFilterValue()
            filt.face_query_filter.uri = uri
            data_name = Name.from_str(name) + [Component.from_bytes(filt.encode())]
            if not await try_remove():
                filt.face_query_filter.uri = None
                filt.face_query_filter.local_uri = uri
                data_name = Name.from_str(name) + [Component.from_bytes(filt.encode())]
                if not await try_remove():
                    print('No face is found')
        finally:
            app.shutdown()

    try:
        face_id = int(face)
        app.run_forever(after_start=run_with_fid(face_id))
    except ValueError:
        app.run_forever(after_start=run_with_uri(face))
