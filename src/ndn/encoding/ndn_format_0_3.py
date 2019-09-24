from typing import Optional, Union, List
from .signer import Signer, DigestSha256
from .tlv_var import VarBinaryStr, BinaryStr
from .tlv_model import TlvModel, InterestNameField, BoolField, UintField, \
    SignatureValueField, OffsetMarker, BytesField, ModelField, NameField, \
    ProcedureArguments


class KeyLocator(TlvModel):
    name = NameField()
    key_digest = BytesField(0x1d)


class SignatureInfo(TlvModel):
    signature_type = UintField(0x1b, fixed_len=1)
    key_locator = ModelField(0x1c, KeyLocator)
    signature_nonce = UintField(0x26)
    signature_time = UintField(0x28)
    signature_seq_num = UintField(0x2a)


class InterestContent(TlvModel):
    _signer = ProcedureArguments()
    _sign_args = ProcedureArguments()
    _sig_cover_part = ProcedureArguments()
    _sig_value_buf = ProcedureArguments()
    _need_digest = ProcedureArguments()
    _digest_buf = ProcedureArguments()

    name = InterestNameField(need_digest=_need_digest,
                             signature_covered_part=_sig_cover_part,
                             digest_buffer=_digest_buf,
                             default="/")
    can_be_prefix = BoolField(0x21, default=False)
    must_be_fresh = BoolField(0x12, default=False)
    nonce = UintField(0x0a, fixed_len=4)
    lifetime = UintField(0x0c)
    hop_limit = UintField(0x22, fixed_len=1)
    _sig_cover_start = OffsetMarker()
    _digest_cover_start = OffsetMarker()
    application_parameters = BytesField(0x24)
    signature_info = ModelField(0x2c, SignatureInfo)
    signature_value = SignatureValueField(0x2e,
                                          interest_sig=True,
                                          signer=_signer,
                                          sign_args=_sign_args,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf)

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        self._sig_cover_part.set_arg(markers, [])
        if self._sign_args.get_arg(markers) is None:
            self._sign_args.set_arg(markers, {})

        if self.signature_info is not None:
            sig_type = self.signature_info.signature_type
            signer = Signer.get_signer(sig_type)
            sign_arg = self._sign_args.get_arg(markers)
            signer.write_signature_info(self.signature_info, **sign_arg)
        else:
            signer = None
        app_param = self.application_parameters
        if (signer is not None) and (app_param is None):
            app_param = b''
            self.application_parameters = b''

        self._need_digest.set_arg(markers, app_param is not None)
        self._signer.set_arg(markers, signer)

        return super().encoded_length(markers)

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        ret = super().encode(wire, offset, markers)
        offset += markers[f'{self._model_name}##encoded_length']
        wire_view = memoryview(ret)

        InterestContent.signature_value.calculate_signature(markers)
        if self._need_digest.get_arg(markers):
            digest_cover_start = self._digest_cover_start.get_arg(markers)
            digest_covered_part = [wire_view[digest_cover_start:offset]]
            sha256 = DigestSha256()
            digest_buf = self._digest_buf.get_arg(markers)
            sha256.write_signature_value(digest_buf, digest_covered_part)

        return ret


class InterestPacket(TlvModel):
    interest = ModelField(0x05, InterestContent)


class MetaInfo(TlvModel):
    content_type = UintField(0x18)
    freshness_period = UintField(0x19)
    final_block_id = BytesField(0x1a)


class DataContent(TlvModel):
    _signer = ProcedureArguments()
    _sign_args = ProcedureArguments()
    _sig_cover_part = ProcedureArguments()
    _sig_value_buf = ProcedureArguments()

    _sig_cover_start = OffsetMarker()
    name = NameField("/")
    meta_info = ModelField(0x14, MetaInfo)
    content = BytesField(0x15)
    signature_info = ModelField(0x16, SignatureInfo)
    signature_value = SignatureValueField(0x17,
                                          interest_sig=True,
                                          signer=_signer,
                                          sign_args=_sign_args,
                                          covered_part=_sig_cover_part,
                                          starting_point=_sig_cover_start,
                                          value_buffer=_sig_value_buf)

    @staticmethod
    def _marker_vars():
        return ['_sig_cover_start', 'sig_cover_part', 'sig_value_buf', 'signer',
                'signer_args']

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        self._sig_cover_part.set_arg(markers, [])
        if self._sign_args.get_arg(markers) is None:
            self._sign_args.set_arg(markers, {})

        if self.signature_info is not None:
            sig_type = self.signature_info.signature_type
            signer = Signer.get_signer(sig_type)
            sign_arg = self._sign_args.get_arg(markers)
            signer.write_signature_info(self.signature_info, **sign_arg)
        else:
            signer = None
        self._signer.set_arg(markers, signer)

        return super().encoded_length(markers)

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        ret = super().encode(wire, offset, markers)
        DataContent.signature_value.calculate_signature(markers)
        return ret


class DataPacket(TlvModel):
    data = ModelField(0x06, DataContent)


class InterestParam:
    can_be_prefix: bool = False
    must_be_fresh: bool = False
    nonce: Optional[int] = None
    lifetime: Optional[int] = 4000
    hop_limit: Optional[int] = None
    signature_type: Optional[int] = None


class DataParam:
    content_type: Optional[int] = 0
    freshness_period: Optional[int] = None
    final_block_id: Optional[BinaryStr] = None
    signature_type: Optional[int] = 0


def make_interest(name: Union[List[Union[BinaryStr, str]], str, BinaryStr],
                  interest_param: InterestParam,
                  app_param: Optional[BinaryStr] = None,
                  **kwargs) -> bytearray:
    interest = InterestPacket()
    interest.interest = InterestContent()
    interest.interest.name = name
    interest.interest.can_be_prefix = interest_param.can_be_prefix
    interest.interest.must_be_fresh = interest_param.must_be_fresh
    interest.interest.nonce = interest_param.nonce
    interest.interest.lifetime = interest_param.lifetime
    interest.interest.hop_limit = interest_param.hop_limit
    interest.interest.application_parameters = app_param
    if interest_param.signature_type is not None:
        interest.interest.signature_info = SignatureInfo()
        interest.interest.signature_info.signature_type = interest_param.signature_type
    return interest.encode(markers={'signer_args': kwargs})


def make_data(name: Union[List[Union[BinaryStr, str]], str, BinaryStr],
              data_param: DataParam,
              content: Optional[BinaryStr] = None,
              **kwargs) -> bytearray:
    data = DataPacket()
    data.data = DataContent()
    data.data.meta_info = MetaInfo()
    data.data.name = name
    data.data.meta_info.content_type = data_param.content_type
    data.data.meta_info.freshness_period = data_param.freshness_period
    data.data.meta_info.final_block_id = data_param.final_block_id
    data.data.content = content
    if data_param.signature_type is not None:
        data.data.signature_info = SignatureInfo()
        data.data.signature_info.signature_type = data_param.signature_type
    return data.encode(markers={'signer_args': kwargs})
