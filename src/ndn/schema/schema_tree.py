import asyncio as aio
from typing import Dict, Any, Type, Optional
from dataclasses import dataclass
from ndn.encoding import is_binary_str, FormalName, NonStrictName, Name, Component, \
    SignaturePtrs, InterestParam, BinaryStr, MetaInfo, parse_data
from ndn.app import NDNApp
from ndn.security import sha256_digest_checker, DigestSha256Signer
from ndn.utils import gen_nonce
from .util import norm_pattern
from . import policy


class NodeExistsError(Exception):
    pattern: str

    def __init__(self, pattern: str):
        self.pattern = pattern


class Node:
    # Properties of nodes
    policies: Dict[Type[policy.Policy], policy.Policy]
    # Prefix of the root. Generally not set for other nodes.
    prefix: FormalName
    # NDNApp, only available by the root
    app: Optional[NDNApp]

    def __init__(self, parent=None):
        self.parent = parent
        # Efficiency is not considered at this draft
        self.children = {}
        self.matches = {}
        self.policies = {}
        self.prefix = []
        self.app = None

    # def make_namespace(self, prefix: NonStrictName):
    #     ret = Node()
    #     self[prefix] = ret
    #     return ret

    # ====== Functions operating on children ======

    def exist(self, key):
        if is_binary_str(key):
            return bytes(key) in self.children
        else:
            return key[:2] in self.matches

    def _get(self, key):
        if is_binary_str(key):
            return self.children[bytes(key)]
        else:
            return self.matches[key[:2]][1]

    def _set(self, key, val):
        if is_binary_str(key):
            self.children[bytes(key)] = val
        else:
            self.matches[key[:2]] = (key[2], val)
        return val

    def __getitem__(self, key: str):
        key_lst = norm_pattern(key)
        cur = self
        for k in key_lst:
            try:
                cur = cur._get(k)
            except KeyError:
                cur = cur._set(k, Node(cur))
        return cur

    def __setitem__(self, key: str, value):
        key_lst = norm_pattern(key)
        cur = self
        for k in key_lst[:-1]:
            try:
                cur = cur._get(k)
            except KeyError:
                cur = cur._set(k, Node(cur))
        if cur.exist(key_lst[-1]):
            raise NodeExistsError(key)
        cur._set(key_lst[-1], value)
        value.parent = cur
        return value

    def _match_step(self, comp: bytes, env, policies):
        policies.update(self.policies)
        chd = self.children.get(comp, None)
        if chd is not None:
            return chd
        typ = Component.get_type(comp)
        match = self.matches.get((0, typ), None)
        if match is not None:
            env[match[0]] = Component.get_value(comp)
            return match[1]
        else:
            return None

    def match(self, name: NonStrictName):
        env = {}
        policies = {}
        cur = self
        name = Name.normalize(name)
        if self.prefix:
            if len(name) < len(self.prefix) or name[:len(self.prefix)] != self.prefix:
                raise ValueError(f'The name f{Name.to_str(name)} does not match with '
                                 f'the prefix of this node {Name.to_str(self.prefix)}')
            pos = len(self.prefix)
        else:
            pos = 0
        while pos < len(name):
            nxt = cur._match_step(bytes(name[pos]), env, policies)
            if not nxt:
                break
            else:
                cur = nxt
                pos += 1
        if pos is None:
            pos = len(name)
        return MatchedNode(root=self, node=cur, name=name, pos=pos, env=env, policies=policies)

    # ====== Functions operating on policies ======

    def get_policy(self, typ: Type[policy.Policy]):
        ret = None
        cur = self
        while ret is None and cur is not None:
            ret = cur.policies.get(typ, None)
            cur = cur.parent
        return ret

    def set_policy(self, typ: Type[policy.Policy], value: policy.Policy):
        if not isinstance(value, typ):
            raise TypeError(f'The policy {value} is not of type {typ}')
        self.policies[typ] = value
        value.node = self

    # ====== Functions on registration  ======

    async def attach(self, app: NDNApp, prefix: NonStrictName):
        prefix = Name.normalize(prefix)
        self.app = app
        # TODO: We do not always want to register all name spaces
        return await self.on_register(self, app, prefix)

    async def detach(self, app: NDNApp):
        raise NotImplementedError('TODO: Not supported yet. Please reset NDNApp.')

    async def on_register(self, root, app: NDNApp, prefix: FormalName):
        self.prefix = prefix
        self.app = app
        if self.matches:
            # If there is a match, have to register
            return await app.register(prefix, root._on_interest_root, root._int_validator, True)
        else:
            for comp, chd in self.children.items():
                if not chd.on_register(root, app, prefix + comp):
                    return False
            return True

    # ====== Functions on Interest processing  ======

    async def _int_validator(self, name: FormalName, sig_ptrs: SignaturePtrs) -> bool:
        match = self.match(name)
        validate_policy = match.policies.get(policy.InterestValidator, None)
        if validate_policy is None:
            return await sha256_digest_checker(name, sig_ptrs)
        if isinstance(validate_policy, policy.InterestValidator):
            return await validate_policy.validate(match, sig_ptrs)
        else:
            raise TypeError(f'The InterestValidator policy is of wrong type. Name={Name.to_str(name)}')

    def _on_interest_root(self, name: FormalName, param: InterestParam,
                          app_param: Optional[BinaryStr], raw_packet: BinaryStr):
        match = self.match(name)
        match.on_interest(param, app_param, raw_packet)

    async def on_interest(self, match, param: InterestParam, app_param: Optional[BinaryStr], raw_packet: BinaryStr):
        # Cache search
        cache_policy = match.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            data_raw = await cache_policy.search(match, match.name, param)
            if data_raw is not None:
                match.root.app.put_raw_packet(data_raw)
                return
        # By design, we do not cache Interest
        # Decrypt app_param
        if app_param:
            ac_policy = match.policies.get(policy.InterestEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.InterestEncryption):
                app_param = await ac_policy.decrypt(match, app_param)
        # Process Interest
        await self.process_int(match, param, app_param, raw_packet)

    async def process_int(self, match, param: InterestParam, app_param: Optional[BinaryStr], raw_packet: BinaryStr):
        # Override this function to customize the processing
        pass

    # ====== Functions on Data processing  ======

    async def process_data(self, match, meta_info: MetaInfo, content: Optional[BinaryStr], raw_packet: BinaryStr):
        # Override this function to customize the processing
        return content

    async def express(self, match, param: InterestParam, app_param: Optional[BinaryStr]):
        # Cache search
        cache_policy = match.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            data_raw = await cache_policy.search(match, match.name, param)
            if data_raw is not None:
                data_name, meta_info, content, _ = parse_data(data_raw, with_tl=False)
                return await self.on_data(match, meta_info, content, data_raw)
        # Encrypt app_param
        if app_param is not None:
            ac_policy = match.policies.get(policy.InterestEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.InterestEncryption):
                app_param = await ac_policy.encrypt(match, app_param)
        # Get validator
        validate_policy = match.policies.get(policy.DataValidator, None)
        if validate_policy and isinstance(validate_policy, policy.DataValidator):
            validator = validate_policy.get_validator(match)
        else:
            validator = sha256_digest_checker  # Change this if possible
        # Get signer
        signer_policy = match.policies.get(policy.InterestSigning, None)
        if signer_policy and isinstance(signer_policy, policy.InterestSigning):
            signer = signer_policy.get_signer(match)
        elif app_param is not None:
            signer = DigestSha256Signer()
        else:
            signer = None
        # Express interest
        data = await match.root.app.express_interest(match.name, app_param, validator, need_raw_packet=True,
                                                     interest_param=param, signer=signer)
        data_name, meta_info, content, data_raw = data
        return await match.on_data(data_name, meta_info, content, data_raw)

    async def on_data(self, match, meta_info: MetaInfo, content: Optional[BinaryStr], raw_packet: BinaryStr):
        # Cache save
        cache_policy = match.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            aio.ensure_future(cache_policy.save(match, match.name, raw_packet))
        # Decrypt content
        if content is not None:
            ac_policy = match.policies.get(policy.DataEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.DataEncryption):
                content = await ac_policy.decrypt(match, content)
        # Process Data
        return await self.process_data(match, meta_info, content, raw_packet)

    async def put_data(self, match, meta_info: MetaInfo, content: Optional[BinaryStr], send_packet: bool = False):
        data_name = match.name
        # Encrypt content
        if content is not None:
            ac_policy = match.policies.get(policy.DataEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.DataEncryption):
                content = await ac_policy.encrypt(match, content)
                data_name = ac_policy.get_encrypted_name(match)
        # Get signer
        signer_policy = match.policies.get(policy.DataSigning, None)
        if signer_policy and isinstance(signer_policy, policy.DataSigning):
            signer = signer_policy.get_signer(match)
        elif content is not None:
            signer = DigestSha256Signer()
        else:
            signer = None
        # Prepare Data packet
        raw_packet = match.root.app.prepare_data(data_name, content, meta_info=meta_info, signer=signer)
        # Cache save
        cache_policy = match.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            aio.ensure_future(cache_policy.save(match, match.name, raw_packet))
        # face.put
        if send_packet:
            match.root.app.put_raw_packet(raw_packet)


@dataclass
class MatchedNode:
    root: Node
    node: Node
    name: FormalName
    pos: int
    env: Dict[str, Any]
    policies: Dict[Type[policy.Policy], policy.Policy]

    def finer_match(self, suffix: NonStrictName):
        env = self.env.copy()
        policies = self.policies.copy()
        suffix = Name.normalize(suffix)
        pos = None
        cur = self.node
        for i, comp in enumerate(suffix):
            nxt = cur._match_step(bytes(comp), env, policies)
            if not nxt:
                pos = i
                break
            else:
                cur = nxt
        if pos is None:
            pos = self.pos + len(suffix)
        else:
            pos = self.pos + pos
        return MatchedNode(root=self.root, node=cur, name=self.name+suffix, pos=pos, env=env, policies=policies)

    def on_interest(self, param: InterestParam, app_param: Optional[BinaryStr], raw_packet: BinaryStr):
        aio.ensure_future(self.node.on_interest(self, param, app_param, raw_packet))

    def on_data(self, data_name: FormalName, meta_info: MetaInfo, content: Optional[BinaryStr], raw_packet: BinaryStr):
        name_len = len(self.name)
        if self.pos == name_len:
            match = self.finer_match(data_name[name_len:])
        else:
            match = MatchedNode(root=self.root, node=self.node, name=data_name, pos=self.pos,
                                env=self.env, policies=self.policies)
        return match.node.on_data(match, meta_info, content, raw_packet)

    def express(self, app_param: Optional[BinaryStr] = None, **kwargs):
        if 'nonce' not in kwargs:
            kwargs['nonce'] = gen_nonce()
        interest_param = InterestParam.from_dict(kwargs)
        return self.node.express(self, interest_param, app_param)

    def put_data(self, content: Optional[BinaryStr] = None, send_packet: bool = False, **kwargs):
        meta_info = MetaInfo.from_dict(kwargs)
        return self.node.put_data(self, meta_info, content, send_packet)

    def app(self) -> NDNApp:
        return self.root.app
