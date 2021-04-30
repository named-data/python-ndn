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
import asyncio as aio
from typing import Dict, Any, Type, Optional
from dataclasses import dataclass
from ..encoding import is_binary_str, FormalName, NonStrictName, Name, Component, \
    SignaturePtrs, InterestParam, BinaryStr, MetaInfo, parse_data, TypeNumber
from ..app import NDNApp
from ..security import sha256_digest_checker, DigestSha256Signer
from ..utils import gen_nonce
from .util import norm_pattern
from . import policy


class NodeExistsError(Exception):
    """
    Raised when trying to create a node which already exists.
    """
    pattern: str

    def __init__(self, pattern: str):
        self.pattern = pattern


class LocalResourceNotExistError(Exception):
    """
    Raised when trying to fetch a local resource that does not exist.
    Used only when :class:`LocalOnly` is attached to the node.
    """
    name: FormalName

    def __init__(self, name: FormalName):
        self.name = name


class Node:
    """
    Node represents a node in the static namespace tree.

    :ivar policies: policies attached to this node
    :vartype policies: Dict[Type[policy.Policy], policy.Policy]
    :ivar prefix: the prefix of the root node of the tree. Generally not set for other nodes.
    :vartype prefix: :any:`FormalName`
    :ivar ~.app: the :any:`NDNApp` this static tree is attached to. Only available at the root.
    :vartype ~.app: Optional[NDNApp]
    """
    policies: Dict[Type[policy.Policy], policy.Policy]
    prefix: FormalName
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
        """
        If it has a child with specified name component or nme pattern.

        :param key: a name component (bytes) or a patten (tuple).
        :return: whether the child node exists
        """
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
        """
        Get a node in the subtree rooted at this node.
        If any node on the path does not exist, this function will create it.

        :param key: the path from this node to the destination. Can contain both components and patterns.
        :return: the desinated node.
        """
        key_lst = norm_pattern(key)
        cur = self
        for k in key_lst:
            try:
                cur = cur._get(k)
            except KeyError:
                cur = cur._set(k, Node(cur))
        return cur

    def __setitem__(self, key: str, value):
        """
        Set a node in the subtree rooted at this node.
        If any node on the path does not exist, this function will create it.

        :param key: the path from this node to the destination. Can contain both components and patterns.
        :param value: the destinated node.
        :return: the same as ``value``
        """
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
        """
        Start from this node, go the path that matches with the name,
        and return the node it reaches when it cannot go further.

        :param name: an NDN name.
        :return: a :class:`MatchedNode`, which contains the destination node and variables matched.
        """
        if self.parent is not None:
            raise ValueError('Node.match() should be called from root')
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
        policies.update(cur.policies)
        return MatchedNode(root=self, node=cur, name=name, pos=pos, env=env, policies=policies)

    # TODO: Apply

    # ====== Functions operating on policies ======

    def get_policy(self, typ: Type[policy.Policy]):
        """
        Get the policy of specified type that applies to this node.
        It can be attached to this node or a parent of this node.

        :param typ: a policy type
        :return: the policy. None if there does not exist one.
        """
        ret = None
        cur = self
        while ret is None and cur is not None:
            ret = cur.policies.get(typ, None)
            cur = cur.parent
        return ret

    def set_policy(self, typ: Type[policy.Policy], value: policy.Policy):
        """
        Attach a policy to this node.

        :param typ: the policy type.
        :param value: the policy to be attached to this node.
        """
        if not isinstance(value, typ):
            raise TypeError(f'The policy {value} is not of type {typ}')
        self.policies[typ] = value
        value.node = self

    # ====== Functions on registration  ======

    async def attach(self, app: NDNApp, prefix: NonStrictName):
        r"""
        Attach this node to a specified :any:`NDNApp`, register all name prefixes.
        This node becomes the root node of the application static tree.
        ``prefix`` is the prefix of the tree, which will be prepended to all names under this tree.
        For example, if ``prefix='/a/blog'``, then the node with path ``/articles`` from this node
        will become ``/a/blog/articles``.

        .. warning::

            The way to register prefixes is still under discussion.
            Currently, we register the nodes that we can reach without going through a pattern.
            Also, there is no ``detach`` function yet, and no means to change the static tree after it's attached.

        :param app: the :any:`NDNApp` to be attached to.
        :param prefix: the prefix of the static tree.
        :return: whether succeeded or not.
        """
        prefix = Name.normalize(prefix)
        self.app = app
        return await self.on_register(self, app, prefix, cached=False)

    # async def detach(self, app: NDNApp):
    #     raise NotImplementedError('TODO: Not supported yet. Please reset NDNApp.')

    async def on_register(self, root, app: NDNApp, prefix: FormalName, cached: bool):
        """
        Called when the root node ``root`` is attached to ``app``, and the :meth:`attach` wants to
        register prefixed under the subtree rooted at this node.

        :param root: the root of the static tree.
        :param app: the :any:`NDNApp` to be attached to.
        :param prefix: the prefix of the static tree.
        :param cached: If there is a cache policy that applies to this node.
        :return: whether succeeded or not.
        """
        # If there is a register policy
        if policy.Register in self.policies:
            return await app.register(prefix, root._on_interest_root, root._int_validator, True)
        # If it is cached with a match or being leaf
        cached = cached or policy.Cache in self.policies
        if cached:
            if self.matches or not self.children:
                return await app.register(prefix, root._on_interest_root, root._int_validator, True)
        # O/w enumerate its children
        for comp, chd in self.children.items():
            if not await chd.on_register(root, app, prefix + [comp], cached=cached):
                return False
        return True

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
        aio.create_task(match.on_interest(param, app_param, raw_packet))

    # ====== Functions on Interest & Data processing (For overriding)  ======

    async def process_int(self, match, param: InterestParam, app_param: Optional[BinaryStr], raw_packet: BinaryStr):
        """
        Processing an incoming Interest packet. Specific node type can override this function to have customized
        processing pipeline.

        .. note::

            This function will not be called if the Interest packet is satisfied with a cached Data packet.

        :param match: the matched node object of this node.
        :param param: the parameters of the Interest packet.
        :param app_param: the ApplicationParameters of the Interest packet.
        :param raw_packet: the raw Interest packet.
        """
        pass

    async def process_data(self, match, meta_info: MetaInfo, content: Optional[BinaryStr], raw_packet: BinaryStr):
        """
        Processing an incoming Data packet. Specific node type can override this function to have customized
        processing pipeline. By default it returns the content.

        :param match: the matched node object of this node.
        :param meta_info: the MetaInfo of the Data packet.
        :param content: the content of the Data packet.
        :param raw_packet: the raw Data packet.
        :return: a tuple, whose first element is data content after processing, and second is a ``dict[str, Any]``
            containing metadata.
        """
        # Override this function to customize the processing
        meta_data = {
            **match.env,
            'content_type': meta_info.content_type,
            'freshness_period': meta_info.freshness_period,
            'final_block_id': meta_info.final_block_id
        }
        return content, meta_data

    async def need(self, match, **kwargs):
        """
        Consume an object corresponding to this node. Specific node type can override this function to have customized
        processing pipeline. For example, a SegmentedNode can do reassembly here.
        By default it sends an Interest packet to fetch a Data.

        :param match: the matched node object of this node.
        :param kwargs: other arguments from user input.
        :return: This is defined by the node type. By default it returns what :meth:`process_data` returns.
            That is, a tuple of contect and metadata dict.
        """
        return await match.express(**kwargs)

    async def provide(self, match, content, **kwargs):
        """
        Produce an object corresponding to this node, and make all generated Data packets available.
        Specific node type can override this function to have customized processing pipeline.
        For example, a SegmentedNode can do segmentation here.
        By default it makes a Data packet out of content and put it into the cache.

        :param match: the matched node object of this node.
        :param content: the content of the object.
        :param kwargs: other arguments from user input.
        """
        return await match.put_data(content, **kwargs)


@dataclass
class MatchedNode:
    r"""
    MatchedNode represents a matched static tree node.
    That is, a node with all name patterns on the path from the root to it assigned to some value.
    For example, if the tree contains a node N on the path ``/a/<b>/<c>``,
    and the user use the Name ``/a/x/y`` to match,
    then a matched node (N, {'b': 'x', 'c': 'y'}) will be returned.

    :ivar root: the root of the static tree.
    :vartype root: Node
    :ivar node: the matched node of the static tree.
    :vartype node: Node
    :ivar name: the name used to match.
    :vartype name: :any:`FormalName`
    :ivar pos: an integer indicating the length the name is matched. Generally, it equals the length of ``name``.
    :vartype pos: int
    :ivar env: a dict containing the value all pattern variables matched on the path.
    :vartype env: Dict[str, Any]
    :ivar policies: a dict collecting all policies that apply to this node.
        For each type of policy, the one attached on the nearst ancestor is collected here.
    :vartype policies: Dict[Type[policy.Policy], policy.Policy]
    """
    root: Node
    node: Node
    name: FormalName
    pos: int
    env: Dict[str, Any]
    policies: Dict[Type[policy.Policy], policy.Policy]

    def finer_match(self, new_name: FormalName):
        """
        Do a finer match based on current match. ``new_name`` must include current ``name`` as its prefix.
        For example, if the current match name is ``/a/b`` and we want to get the matched node for ``/a/b/c``,
        then we can call finer_match with ``/a/b/c``.

        :param new_name: the new name to be matched. Must include current ``name`` as its prefix.
        :return: the new matched node.
        """
        name_len = len(self.name)
        if self.pos < name_len:
            # match = self.finer_match(data_name[name_len:])
            return MatchedNode(root=self.root, node=self.node, name=new_name, pos=self.pos,
                               env=self.env, policies=self.policies)

        env = self.env.copy()
        policies = self.policies.copy()
        pos = None
        cur = self.node
        for i in range(name_len, len(new_name)):
            comp = new_name[i]
            nxt = cur._match_step(bytes(comp), env, policies)
            if not nxt:
                pos = i
                break
            else:
                cur = nxt
        if pos is None:
            pos = len(new_name)
        policies.update(cur.policies)
        return MatchedNode(root=self.root, node=cur, name=new_name, pos=pos, env=env, policies=policies)

    async def on_interest(self, param: InterestParam, app_param: Optional[BinaryStr], raw_packet: BinaryStr):
        """
        Called when an Interest packet comes.
        It looks up the cache and returns a Data packet if it exists.
        Otherwise, it decrypts ApplicationParameters and calls the node's ``process_int`` function.

        :param param: the parameters of the incoming Interest.
        :param app_param: the ApplicationParameters of the Interest.
        :param raw_packet: the raw Interest packet.
        """
        # Cache search
        cache_policy = self.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            data_raw = await cache_policy.search(self, self.name, param)
            if data_raw is not None:
                self.root.app.put_raw_packet(data_raw)
                return
        # By design, we do not cache Interest
        # Decrypt app_param
        if app_param:
            ac_policy = self.policies.get(policy.InterestEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.InterestEncryption):
                app_param = await ac_policy.decrypt(self, app_param)
        # Process Interest
        await self.node.process_int(self, param, app_param, raw_packet)

    async def on_data(self, meta_info: MetaInfo, content: Optional[BinaryStr], raw_packet: BinaryStr):
        """
        Called when a Data packet comes.
        It saves the Data packet into the cache, decrypts the content, and calls
        the node's ``process_data`` function.

        :param meta_info: the MetaInfo of the incoming Data packet.
        :param content: the content of the Data.
        :param raw_packet: the raw Data packet.
        :return: whatever ``process_data`` returns.
        """
        # Cache save
        if policy.LocalOnly not in self.policies:
            cache_policy = self.policies.get(policy.Cache, None)
            if cache_policy and isinstance(cache_policy, policy.Cache):
                # aio.ensure_future(cache_policy.save(self, self.name, raw_packet))
                # self.name may change after this time point, so we have to wait until its finish
                await cache_policy.save(self, self.name, raw_packet)
        # Decrypt content
        if content is not None:
            ac_policy = self.policies.get(policy.DataEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.DataEncryption):
                content = await ac_policy.decrypt(self, content)
        # Process Data
        return await self.node.process_data(self, meta_info, content, raw_packet)

    async def express(self, app_param: Optional[BinaryStr] = None, **kwargs):
        """
        Try to fetch the data, called by the node's need function.
        It will search the local cache, and examines the local resource.
        If the corresponding Data cannot be found in the two places,
        it encrypts the app_param and expresses the Interest.

        .. note::

            This function only sends out an Interest packet when the Data is not cached locally.

        :param app_param: the ApplicationParameter of the Interest.
        :param kwargs: other parameters of the Interest.
        :return: whatever ``process_data`` returns.
            Generally this function is only called at the default node,
            so the return value is a tuple of the content and a dict containing metadata.
        """
        if 'nonce' not in kwargs:
            kwargs['nonce'] = gen_nonce()
        param = InterestParam.from_dict(kwargs)

        # Cache search
        cache_policy = self.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            data_raw = await cache_policy.search(self, self.name, param)
            if data_raw is not None:
                with_tl = (data_raw[0] == TypeNumber.DATA)
                data_name, meta_info, content, _ = parse_data(data_raw, with_tl=with_tl)
                return await self.finer_match(data_name).on_data(meta_info, content, data_raw)
        # Local only?
        local_policy = self.policies.get(policy.LocalOnly, None)
        if local_policy:
            raise LocalResourceNotExistError(self.name)
        # Encrypt app_param
        if app_param is not None:
            ac_policy = self.policies.get(policy.InterestEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.InterestEncryption):
                app_param = await ac_policy.encrypt(self, app_param)
        # Get validator TODO: How can we pass information out?
        validate_policy = self.policies.get(policy.DataValidator, None)
        if validate_policy and isinstance(validate_policy, policy.DataValidator):
            validator = validate_policy.get_validator(self)
        else:
            validator = sha256_digest_checker  # Change this if possible
        # Get signer
        signer_policy = self.policies.get(policy.InterestSigning, None)
        if signer_policy and isinstance(signer_policy, policy.InterestSigning):
            signer = signer_policy.get_signer(self)
        elif app_param is not None:
            signer = DigestSha256Signer()
        else:
            signer = None
        # Express interest
        data = await self.root.app.express_interest(self.name, app_param, validator, need_raw_packet=True,
                                                    interest_param=param, signer=signer)
        data_name, meta_info, content, data_raw = data
        return await self.finer_match(data_name).on_data(meta_info, content, data_raw)

    def need(self, **kwargs):
        """
        Consume an object corresponding to this node. Specific node type may have customized
        processing pipeline. For example, a SegmentedNode can do reassembly here.
        By default it sends an Interest packet to fetch a Data.

        MatchedNode's ``need`` simply calls the node's ``need`` function.

        :param kwargs: arguments from user input.
        :return: the object needed, whose format is defined by specific node type.
            By default, it returns a tuple of the content and a dict of metadata.
        """
        return self.node.need(self, **kwargs)

    def provide(self, content, **kwargs):
        """
        Produce an object corresponding to this node, and make all generated Data packets available.
        Specific node type may have customized processing pipeline.
        For example, a SegmentedNode can do segmentation here.
        By default it makes a Data packet out of content and put it into the cache.

        MatchedNode's ``provide`` simply calls the node's ``provide`` function.

        :param content: the content of the object.
        :param kwargs: other arguments from user input. Defined by specific node type.
        """
        return self.node.provide(self, content, **kwargs)

    async def put_data(self, content: Optional[BinaryStr] = None, send_packet: bool = False, **kwargs):
        """
        Generate the Data packet out of content.
        This function encrypts the content, encodes and signs the packet, saves it into the cache,
        and optionally sends it to the face.
        This function is called by the node's ``provide`` function.

        :param content: the Data content.
        :param send_packet: whether sends the Data packet to the face.
        :param kwargs: other arguments generating the Data packet.
        """
        meta_info = MetaInfo.from_dict(kwargs)
        data_name = self.name
        # Encrypt content
        if content is not None:
            ac_policy = self.policies.get(policy.DataEncryption, None)
            if ac_policy and isinstance(ac_policy, policy.DataEncryption):
                content = await ac_policy.encrypt(self, content)
        # Get signer
        signer_policy = self.policies.get(policy.DataSigning, None)
        if signer_policy and isinstance(signer_policy, policy.DataSigning):
            signer = signer_policy.get_signer(self)
        else:
            signer = self.root.app.keychain.get_signer(kwargs)
        # Prepare Data packet
        raw_packet = self.root.app.prepare_data(data_name, content, meta_info=meta_info, signer=signer)
        # Cache save
        cache_policy = self.policies.get(policy.Cache, None)
        if cache_policy and isinstance(cache_policy, policy.Cache):
            # aio.ensure_future(cache_policy.save(self, self.name, raw_packet))
            await cache_policy.save(self, self.name, raw_packet)
        # face.put
        if send_packet:
            self.root.app.put_raw_packet(raw_packet)

    def app(self) -> NDNApp:
        """
        The :any:`NDNApp` the static tree is attached to.

        :return: the :any:`NDNApp`.
        """
        return self.root.app
