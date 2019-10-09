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
from ..encoding import NonStrictName, Name, Component
from ..app import NDNApp
from ..types import InterestTimeout


async def segment_fetcher(app: NDNApp, name: NonStrictName, timeout=4000, retry_times=3,
                          validator=None, must_be_fresh=True):
    """
    An async-generator to fetch a segmented object. Interests are issued one by one.

    :param app: NDN Application
    :param name: Name prefix of Data
    :param timeout: Timeout value, in milliseconds
    :param retry_times: Times for retry
    :param validator: Validator
    :param must_be_fresh: MustBeFresh field of Interest
    :return: Data segments in order.
    """
    async def retry(first):
        nonlocal name
        trial_times = 0
        while True:
            future = app.express_interest(name, validator=validator, can_be_prefix=first,
                                          must_be_fresh=must_be_fresh, lifetime=timeout)
            try:
                return await future
            except InterestTimeout:
                trial_times += 1
                if trial_times >= retry_times:
                    raise

    name = Name.normalize(name)
    # First Interest
    name, meta, content = await retry(True)
    # If it's not segmented
    if Component.get_type(name[-1]) != Component.TYPE_SEGMENT:
        yield content
        return
    # If it's segmented
    if Component.to_number(name[-1]) == 0:
        yield content
        if meta.final_block_id == name[-1]:
            return
        seg_no = 1
    else:
        # If it's not segment 0, starting from 0
        seg_no = 0
    # Following Interests
    while True:
        name[-1] = Component.from_segment(seg_no)
        name, meta, content = await retry(False)
        yield content
        if meta.final_block_id == name[-1]:
            return
        seg_no += 1
