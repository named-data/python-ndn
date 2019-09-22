from typing import Optional
from .signer import Signer, DigestSha256
from .tlv_var import VarBinaryStr
from .tlv_model import TlvModel, InterestNameField, BoolField, UintField, \
    SignatureField, OffsetMarker, BytesField, ModelField, NameField


class InterestContent(TlvModel):
    name = InterestNameField("/")
    can_be_prefix = BoolField(0x21, False)
    must_be_fresh = BoolField(0x12, False)
    nonce = UintField(0x0a, fixed_len=4)
    lifetime = UintField(0x0c, 4000)
    hop_limit = UintField(0x22, fixed_len=1)
    _sig_cover_start = OffsetMarker()
    _digest_cover_start = OffsetMarker()
    application_paramaters = BytesField(0x24)
    signature_type = SignatureField(info_typ=0x2c, value_typ=0x2e, interest_sig=True)

    @staticmethod
    def _marker_vars():
        return ['_sig_cover_start', 'sig_cover_part', 'sig_value_buf', 'signer',
                'need_digest', '_digest_cover_start', 'digest_pos', 'digest_buf',
                'signer_args']

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        markers['sig_cover_part'] = []
        if 'signer_args' not in markers:
            markers['signer_args'] = {}

        sig_type = self.signature_type
        app_param = self.application_paramaters
        signer = (Signer.get_signer(sig_type)
                  if sig_type is not None
                  else None)
        if (signer is not None) and (app_param is None):
            app_param = b''
            self.application_paramaters = b''
        markers['need_digest'] = app_param is not None
        markers['signer'] = signer

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

        self._fill_in_signature(markers)
        if markers['need_digest']:
            digest_covered_part = [wire_view[markers['_digest_cover_start']:offset]]
            sha256 = DigestSha256()
            sha256.write_signature_value(markers['digest_buf'], digest_covered_part)

        return ret


class InterestPacket(TlvModel):
    interest = ModelField(0x05, InterestContent)


class MetaInfo(TlvModel):
    content_type = UintField(0x18)
    freshness_period = UintField(0x19)
    final_block_id = BytesField(0x1a)


class DataContent(TlvModel):
    _sig_cover_start = OffsetMarker()
    name = NameField("/")
    meta_info = ModelField(0x14, MetaInfo)
    content = BytesField(0x15)
    signature_type = SignatureField(info_typ=0x16, value_typ=0x17, interest_sig=False)

    @staticmethod
    def _marker_vars():
        return ['_sig_cover_start', 'sig_cover_part', 'sig_value_buf', 'signer',
                'signer_args']

    def encoded_length(self, markers: Optional[dict] = None) -> int:
        if markers is None:
            markers = {}
        markers['sig_cover_part'] = []
        if 'signer_args' not in markers:
            markers['signer_args'] = {}

        sig_type = self.signature_type
        signer = (Signer.get_signer(sig_type)
                  if sig_type is not None
                  else None)
        markers['signer'] = signer

        return super().encoded_length(markers)

    def encode(self,
               wire: VarBinaryStr = None,
               offset: int = 0,
               markers: Optional[dict] = None) -> VarBinaryStr:
        if markers is None:
            markers = {}
        ret = super().encode(wire, offset, markers)
        self._fill_in_signature(markers)
        return ret


class DataPacket(TlvModel):
    data = ModelField(0x06, DataContent)
