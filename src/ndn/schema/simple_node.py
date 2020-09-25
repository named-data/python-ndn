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
# TODO: Change these names
from .schema_tree import Node
from .util import norm_pattern
from ..encoding import Name, Component, TlvModel, NameField, ContentType
from ..types import InterestTimeout
from ..utils import timestamp


class LocalResource(Node):
    """
    LocalResource is a custom node that preloads some data.
    When need() is called, it returns the loaded data directly.
    This node type does not interact with the network.
    """
    def __init__(self, parent=None, data=None):
        super().__init__(parent)
        self.data = data

    async def on_register(self, root, app, prefix, cached: bool):
        self.prefix = prefix
        self.app = app
        return await app.register(prefix, root._on_interest_root, root._int_validator, True)

    async def need(self, match, **kwargs):
        return self.data

    async def provide(self, match, content, **kwargs):
        self.data = content


class SegmentedNode(Node):
    """
    SegmentedNode represents a segmented object.
    The segmented object is composed with multiple Data packets,
    whose name have a suffix "/seg=seg_no" attached to the object's name.
    The ``provide`` function handles segmentation, and the ``need`` function handles reassembly.

    .. note::

        Currently, the fetching pipeline is a simple one-by-one pipeline.
        where only one Interest will be in-flight at one time.
    """
    SEGMENT_PATTERN = norm_pattern('<seg:seg_no>')[0]
    SEGMENT_SIZE = 4400

    def __init__(self, parent=None, timeout=4000, retry_times=3, segment_size=SEGMENT_SIZE):
        super().__init__(parent)
        self._set(self.SEGMENT_PATTERN, Node())
        self.timeout = timeout
        self.retry_times = retry_times
        self.segment_size = segment_size

    async def retry(self, submatch, must_be_fresh):
        trial_times = 0
        while True:
            try:
                return await submatch.need(must_be_fresh=must_be_fresh, lifetime=self.timeout, can_be_prefix=False)
            except InterestTimeout:
                trial_times += 1
                if trial_times >= self.retry_times:
                    raise

    async def need(self, match, **kwargs):
        if match.pos < len(match.name):
            raise ValueError(f'{Name.to_str(match.name)} does not match with the structure')
        subname = match.name + [None]
        must_be_fresh = kwargs.get('must_be_fresh', True)
        contents = []
        cur = 0
        while True:
            subname[-1] = Component.from_segment(cur)
            submatch = match.finer_match(subname)
            segment, meta_data = await self.retry(submatch, must_be_fresh)
            contents.append(segment)
            if meta_data['final_block_id'] == subname[-1]:
                break
            cur += 1
        ret = b''.join(contents)
        meta_data_ret = {
            **match.env,
            'content_type': meta_data['content_type'],
            'block_count': cur + 1,
            'freshness_period': meta_data['freshness_period']
        }
        return ret, meta_data_ret

    async def provide(self, match, content, **kwargs):
        seg_cnt = (len(content) + self.segment_size - 1) // self.segment_size
        subname = match.name + [None]
        final_block_id = Component.from_segment(seg_cnt - 1)
        for i in range(seg_cnt):
            subname[-1] = Component.from_segment(i)
            submatch = match.finer_match(subname)
            kwargs['final_block_id'] = final_block_id
            await submatch.provide(content[i*self.segment_size:(i+1)*self.segment_size], **kwargs)

    async def process_int(self, match, param, app_param, raw_packet):
        if match.pos == len(match.name):
            submatch = match.finer_match(match.name + [Component.from_segment(0)])
            return await submatch.on_interest(param, None, raw_packet)


class RDRNode(Node):
    """
    RDRNode represents a versioned and segmented object whose encoding follows the RDR protocol.
    Its ``provide`` function generates the metadata packet, and ``need`` function handles version discovery.
    """
    class MetaDataValue(TlvModel):
        name = NameField()

    class MetaData(Node):
        VERSION_PATTERN = norm_pattern('<v:timestamp>')[0]
        FRESHNESS_PERIOD = 10

        def __init__(self, parent=None):
            super().__init__(parent)
            self._set(self.VERSION_PATTERN, Node(self))

        def make_metadata(self, match):
            metadata = RDRNode.MetaDataValue()
            metadata.name = match.name[:-1] + [Component.from_version(self.parent.timestamp)]
            return metadata.encode()

        async def process_int(self, match, param, app_param, raw_packet):
            if match.pos == len(match.name) and self.parent.timestamp is not None and param.can_be_prefix:
                metaname = match.name + [Component.from_version(timestamp())]
                submatch = match.finer_match(metaname)
                await submatch.put_data(self.make_metadata(match), send_packet=True,
                                        freshness_period=self.FRESHNESS_PERIOD)

        async def need(self, match, **kwargs):
            if self.parent.timestamp is None:
                return await super().need(match, **kwargs)
            else:
                meta_info = {
                    **match.env,
                    'content_type': ContentType.BLOB,
                    'freshness_period': self.FRESHNESS_PERIOD,
                    'final_block_id': None
                }
                return self.make_metadata(match), meta_info

    def __init__(self, parent=None, **kwargs):
        super().__init__(parent)
        self['/32=metadata'] = RDRNode.MetaData(self)
        self['<v:timestamp>'] = SegmentedNode(self, **kwargs)
        self.timestamp = None

    async def need(self, match, **kwargs):
        submatch = match.finer_match(match.name + [Component.from_str('32=metadata')])
        lifetime = kwargs.get('lifetime', None)
        meta_int_param = {'lifetime': lifetime} if lifetime else {}
        metadata_val, _ = await submatch.need(must_be_fresh=True, can_be_prefix=True, **meta_int_param)
        metadata = RDRNode.MetaDataValue.parse(metadata_val, ignore_critical=True)

        submatch = match.finer_match(metadata.name)
        return await submatch.need(**kwargs)

    async def provide(self, match, content, **kwargs):
        self.timestamp = timestamp()
        submatch = match.finer_match(match.name + [Component.from_version(self.timestamp)])
        await submatch.provide(content, **kwargs)
