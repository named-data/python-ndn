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
import datetime
from ...appv2 import NDNApp
from ...app_support.nfd_mgmt import GeneralStatus
from .utils import express_interest


def add_parser(subparsers):
    parser = subparsers.add_parser('Get-Status', aliases=['status'])
    parser.set_defaults(executor=execute)


def execute(_args: argparse.Namespace):
    app = NDNApp()

    async def after_start():
        try:
            data = await express_interest(app, "/localhost/nfd/status/general")

            msg = GeneralStatus.parse(data)

            print('General status:')
            print(f'{"version":>25}\t{msg.nfd_version}')
            st_time = datetime.datetime.fromtimestamp(msg.start_timestamp / 1000)
            print(f'{"startTime":>25}\t{st_time.strftime("%Y-%m-%d %H:%M:%S.%f")}')
            cur_time = datetime.datetime.fromtimestamp(msg.current_timestamp / 1000)
            print(f'{"currentTime":>25}\t{cur_time.strftime("%Y-%m-%d %H:%M:%S.%f")}')
            up_time = cur_time - st_time
            print(f'{"upTime":>25}\t{up_time}')
            print(f'{"nNameTreeEntries":>25}\t{msg.n_name_tree_entries}')
            print(f'{"nFibEntries":>25}\t{msg.n_fib_entries}')
            print(f'{"nPitEntries":>25}\t{msg.n_pit_entries}')
            print(f'{"nMeasurementsEntries":>25}\t{msg.n_measurement_entries}')
            print(f'{"nCsEntries":>25}\t{msg.n_cs_entries}')
            print(f'{"nInInterests":>25}\t{msg.n_in_interests}')
            print(f'{"nOutInterests":>25}\t{msg.n_out_interests}')
            print(f'{"nInData":>25}\t{msg.n_in_data}')
            print(f'{"nOutData":>25}\t{msg.n_out_data}')
            print(f'{"nInNacks":>25}\t{msg.n_in_nacks}')
            print(f'{"nOutNacks":>25}\t{msg.n_out_nacks}')
            print(f'{"nSatisfiedInterests":>25}\t{msg.n_satisfied_interests}')
            print(f'{"nUnsatisfiedInterests":>25}\t{msg.n_unsatisfied_interests}')
        finally:
            app.shutdown()

    app.run_forever(after_start())
