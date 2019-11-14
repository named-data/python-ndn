TLV Model
=========

.. automodule:: ndn.encoding.tlv_model

    .. autoexception:: DecodeError
        :members:

    .. autoexception:: IncludeBaseError
        :members:

    .. autoclass:: IncludeBase
        :members:

    .. autoclass:: Field
        :members: __get__, __set__, encode_into, encoded_length, get_value, parse_from, skipping_process

    .. autoclass:: ProcedureArgument
        :members: __get__, __set__, get_arg, set_arg
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: OffsetMarker
        :exclude-members: encoded_length, encoded_into, parse_from, skipping_process

    .. autoclass:: UintField
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: BoolField
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: NameField
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: BytesField
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: ModelField
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: RepeatedField
        :exclude-members: encoded_length, encoded_into, parse_from

    .. autoclass:: TlvModelMeta
        :members:

    .. autoclass:: TlvModel
        :members: __eq__, asdict, encode, encoded_length, parse
