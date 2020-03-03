# TODO: Change these names
from .schema_tree import Node
from .util import norm_pattern
from ..encoding import Name, Component, TlvModel, NameField
from ..types import InterestTimeout
from ..utils import timestamp


class LocalResource(Node):
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
            submatch.provide(content[i*self.segment_size:(i+1)*self.segment_size], **kwargs)

    async def process_int(self, match, param, app_param, raw_packet):
        if match.pos == len(match.name):
            submatch = match.finer_match(match.name + [Component.from_segment(0)])
            return await submatch.on_interest(param, None, raw_packet)


class RDRNode(Node):
    class MetaDataValue(TlvModel):
        name = NameField()

    class MetaData(Node):
        VERSION_PATTERN = norm_pattern('<v:timestamp>')[0]

        def __init__(self, parent=None):
            super().__init__(parent)
            self._set(self.VERSION_PATTERN, Node(self))

        async def process_int(self, match, param, app_param, raw_packet):
            if match.pos == len(match.name) and self.parent.timestamp is not None and param.can_be_prefix:
                metadata = RDRNode.MetaDataValue()
                metadata.name = match.name[:-1] + [Component.from_version(self.parent.timestamp)]
                metaname = match.name + [Component.from_version(timestamp())]
                submatch = match.finer_match(metaname)
                await submatch.put_data(metadata.encode(), send_packet=True, freshness_period=10)

    def __init__(self, parent=None, **kwargs):
        super().__init__(parent)
        self['/32=metadata'] = RDRNode.MetaData(self)
        self['<v:timestamp>'] = SegmentedNode(self, **kwargs)
        self.timestamp = None

    async def need(self, match, **kwargs):
        submatch = match.finer_match(match.name + [Component.from_str('32=metadata')])
        lifetime = kwargs.get('lifetime', None)
        meta_int_param = {'lifetime': lifetime} if lifetime else {}
        metadata_val = await submatch.need(must_be_fresh=True, can_be_prefix=True, **meta_int_param)
        metadata = RDRNode.MetaDataValue.parse(metadata_val, ignore_critical=True)

        submatch = match.finer_match(metadata.name)
        return await submatch.need(**kwargs)

    async def provide(self, match, content, **kwargs):
        self.timestamp = timestamp()
        submatch = match.finer_match(match.name + [Component.from_version(self.timestamp)])
        submatch.provide(content, **kwargs)
