from typing import Optional, Union, List
from .name import Name, Component
from .signer import Signer, DigestSha256
from .tlv_var import VarBinaryStr, BinaryStr
from .tlv_model import TlvModel, InterestNameField, BoolField, UintField, \
    SignatureValueField, OffsetMarker, BytesField, ModelField, NameField, \
    ProcedureArgument


class TypeNumber:
    INTEREST = 0x05
    DATA = 0x06

    NAME = Name.TYPE_NAME
    GENERIC_NAME_COMPONENT = Component.TYPE_GENERIC
    IMPLICIT_SHA256_DIGEST_COMPONENT = Component.TYPE_IMPLICIT_SHA256
    PARAMETERS_SHA256_DIGEST_COMPONENT = Component.TYPE_PARAMETERS_SHA256

    CAN_BE_PREFIX = 0x21
    MUST_BE_FRESH = 0x12
    FORWARDING_HINT = 0x1e
    NONCE = 0x0a
    INTEREST_LIFETIME = 0x0c
    HOP_LIMIT = 0x22
    APPLICATION_PARAMETERS = 0x24
    INTEREST_SIGNATURE_INFO = 0x2c
    INTEREST_SIGNATURE_VALUE = 0x2e

    META_INFO = 0x14
    CONTENT = 0x15
    SIGNATURE_INFO = 0x16
    SIGNATURE_VALUE = 0x17
    CONTENT_TYPE = 0x18
    FRESHNESS_PERIOD = 0x19
    FINAL_BLOCK_ID = 0x1a

    SIGNATURE_TYPE = 0x1b
    KEY_LOCATOR = 0x1c
    KEY_DIGEST = 0x1d
    SIGNATURE_NONCE = 0x26
    SIGNATURE_TIME = 0x28
    SIGNATURE_SEQ_NUM = 0x2a

    DELEGATION = 0x1f
    PREFERENCE = 0x1e


class KeyLocator(TlvModel):
    name = NameField()
    key_digest = BytesField(TypeNumber.KEY_DIGEST)


class SignatureInfo(TlvModel):
    signature_type = UintField(TypeNumber.SIGNATURE_TYPE, fixed_len=1)
    key_locator = ModelField(TypeNumber.KEY_LOCATOR, KeyLocator)
    signature_nonce = UintField(TypeNumber.SIGNATURE_NONCE)
    signature_time = UintField(TypeNumber.SIGNATURE_TIME)
    signature_seq_num = UintField(TypeNumber.SIGNATURE_SEQ_NUM)


class InterestContent(TlvModel):
    _signer = ProcedureArgument()
    _sign_args = ProcedureArgument()
    _sig_cover_part = ProcedureArgument()
    _sig_value_buf = ProcedureArgument()
    _need_digest = ProcedureArgument()
    _digest_buf = ProcedureArgument()

    name = InterestNameField(need_digest=_need_digest,
                             signature_covered_part=_sig_cover_part,
                             digest_buffer=_digest_buf,
                             default="/")
    can_be_prefix = BoolField(TypeNumber.CAN_BE_PREFIX, default=False)
    must_be_fresh = BoolField(TypeNumber.MUST_BE_FRESH, default=False)
    nonce = UintField(TypeNumber.NONCE, fixed_len=4)
    lifetime = UintField(TypeNumber.INTEREST_LIFETIME)
    hop_limit = UintField(TypeNumber.HOP_LIMIT, fixed_len=1)
    _sig_cover_start = OffsetMarker()
    _digest_cover_start = OffsetMarker()
    application_parameters = BytesField(TypeNumber.APPLICATION_PARAMETERS)
    signature_info = ModelField(TypeNumber.INTEREST_SIGNATURE_INFO, SignatureInfo)
    signature_value = SignatureValueField(TypeNumber.INTEREST_SIGNATURE_VALUE,
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
    _sign_args = ProcedureArgument()
    interest = ModelField(TypeNumber.INTEREST, InterestContent, [_sign_args])


class MetaInfo(TlvModel):
    content_type = UintField(TypeNumber.CONTENT_TYPE)
    freshness_period = UintField(TypeNumber.FRESHNESS_PERIOD)
    final_block_id = BytesField(TypeNumber.FINAL_BLOCK_ID)


class DataContent(TlvModel):
    _signer = ProcedureArgument()
    _sign_args = ProcedureArgument()
    _sig_cover_part = ProcedureArgument()
    _sig_value_buf = ProcedureArgument()

    _sig_cover_start = OffsetMarker()
    name = NameField("/")
    meta_info = ModelField(TypeNumber.META_INFO, MetaInfo)
    content = BytesField(TypeNumber.CONTENT)
    signature_info = ModelField(TypeNumber.SIGNATURE_INFO, SignatureInfo)
    signature_value = SignatureValueField(TypeNumber.SIGNATURE_VALUE,
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
    _sign_args = ProcedureArgument()
    data = ModelField(TypeNumber.DATA, DataContent, [_sign_args])


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
    markers = {}
    interest._sign_args.set_arg(markers, kwargs)
    return interest.encode(markers=markers)


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
    markers = {}
    data._sign_args.set_arg(markers, kwargs)
    return data.encode(markers=markers)
