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
from ...app_support.nfd_mgmt import FaceStatusMsg, FaceQueryFilter, FaceQueryFilterValue, parse_response
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('Get-Face', aliases=['face', 'gf'])
    parser.add_argument('face', metavar='FACE', nargs='?', default='',
                        help='FaceID or URI of specified face')
    parser.set_defaults(executor=execute)


def execute(args: argparse.Namespace):
    app = NDNApp()

    async def list_face():
        try:
            data = await express_interest(app, "/localhost/nfd/faces/list")
            msg = FaceStatusMsg.parse(data)
            # TODO: Should calculate the length instead of using a fixed number
            print(f'{"FaceID":7}{"RemoteURI":<30}\t{"LocalURI":<30}')
            print(f'{"------":7}{"---------":<30}\t{"--------":<30}')
            for f in msg.face_status:
                print(f'{f.face_id:<7}{f.uri:<30}\t{f.local_uri:<30}')
        finally:
            app.shutdown()

    async def inspect_face(face_id, face_uri):
        async def exec_query():
            data = await express_interest(app, data_name)
            if not data:
                return False
            elif data[0] == 0x65:
                msg = parse_response(data)
                print('Query failed with response', msg['status_code'], msg['status_text'])
            else:
                msg = FaceStatusMsg.parse(data)
                for f in msg.face_status:
                    print()
                    print(f'{"Face ID":>12}\t{f.face_id}')
                    print(f'{"Remote URI":>12}\t{f.uri}')
                    print(f'{"Local URI":>12}\t{f.local_uri}')
                    print(f'{"Scope":>12}\t{f.face_scope.name}')
                    print(f'{"Persistency":>12}\t{f.face_persistency.name}')
                    print(f'{"Link Type":>12}\t{f.link_type.name}')
                    if f.mtu:
                        print(f'{"MTU":>12}\t{f.mtu}')
                    else:
                        print(f'{"MTU":>12}\t-')
                    print(f'{"Counter IN":>12}\t{f.n_in_interests}i {f.n_in_data}d '
                          f'{f.n_in_nacks}n {f.n_in_bytes}B')
                    print(f'{"Counter OUT":>12}\t{f.n_out_interests}i {f.n_out_data}d '
                          f'{f.n_out_nacks}n {f.n_out_bytes}B')
                    print(f'{"Flags":>12}\t{f.flags}')
            return True

        name = "/localhost/nfd/faces/query"
        filt = FaceQueryFilter()
        filt.face_query_filter = FaceQueryFilterValue()
        if face_id is not None:
            filt.face_query_filter.face_id = face_id
            data_name = Name.from_str(name) + [Component.from_bytes(filt.encode())]
            if not await exec_query():
                print('No face is found')
        else:
            filt.face_query_filter.uri = face_uri
            data_name = Name.from_str(name) + [Component.from_bytes(filt.encode())]
            if not await exec_query():
                filt.face_query_filter.uri = None
                filt.face_query_filter.local_uri = face_uri
                data_name = Name.from_str(name) + [Component.from_bytes(filt.encode())]
                if not await exec_query():
                    print('No face is found')
        app.shutdown()

    face = args.face
    if face:
        try:
            face_id = int(face)
            face_uri = None
        except ValueError:
            face_id = None
            face_uri = face
        app.run_forever(inspect_face(face_id, face_uri))
    else:
        app.run_forever(list_face())
