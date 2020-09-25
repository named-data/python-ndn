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
from ndn.utils import timestamp
from ndn.app import NDNApp
from ndn.encoding import Name, Component

SEGMENT_SIZE = 4400


def main():
    if len(sys.argv) <= 2:
        print(f'Usage: {sys.argv[0]} <name> <file>')
        exit(0)
    logging.basicConfig(format='[{asctime}]{levelname}:{message}',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        level=logging.INFO,
                        style='{')

    app = NDNApp()
    name = Name.normalize(sys.argv[1])
    name.append(Component.from_version(timestamp()))

    with open(sys.argv[2], 'rb') as f:
        data = f.read()
        seg_cnt = (len(data) + SEGMENT_SIZE - 1) // SEGMENT_SIZE
        packets = [app.prepare_data(name + [Component.from_segment(i)],
                                    data[i*SEGMENT_SIZE:(i+1)*SEGMENT_SIZE],
                                    freshness_period=10000,
                                    final_block_id=Component.from_segment(seg_cnt - 1))
                   for i in range(seg_cnt)]
    print(f'Created {seg_cnt} chunks under name {Name.to_str(name)}')

    @app.route(name)
    def on_interest(int_name, _int_param, _app_param):
        if Component.get_type(int_name[-1]) == Component.TYPE_SEGMENT:
            seg_no = Component.to_number(int_name[-1])
        else:
            seg_no = 0
        if seg_no < seg_cnt:
            app.put_raw_packet(packets[seg_no])

    app.run_forever()


if __name__ == '__main__':
    main()
