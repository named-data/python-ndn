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
