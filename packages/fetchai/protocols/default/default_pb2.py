# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: default.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\rdefault.proto\x12\x1a\x61\x65\x61.fetchai.default.v1_0_0"\xb6\x06\n\x0e\x44\x65\x66\x61ultMessage\x12N\n\x05\x62ytes\x18\x05 \x01(\x0b\x32=.aea.fetchai.default.v1_0_0.DefaultMessage.Bytes_PerformativeH\x00\x12J\n\x03\x65nd\x18\x06 \x01(\x0b\x32;.aea.fetchai.default.v1_0_0.DefaultMessage.End_PerformativeH\x00\x12N\n\x05\x65rror\x18\x07 \x01(\x0b\x32=.aea.fetchai.default.v1_0_0.DefaultMessage.Error_PerformativeH\x00\x1a\xe4\x01\n\tErrorCode\x12V\n\nerror_code\x18\x01 \x01(\x0e\x32\x42.aea.fetchai.default.v1_0_0.DefaultMessage.ErrorCode.ErrorCodeEnum"\x7f\n\rErrorCodeEnum\x12\x18\n\x14UNSUPPORTED_PROTOCOL\x10\x00\x12\x12\n\x0e\x44\x45\x43ODING_ERROR\x10\x01\x12\x13\n\x0fINVALID_MESSAGE\x10\x02\x12\x15\n\x11UNSUPPORTED_SKILL\x10\x03\x12\x14\n\x10INVALID_DIALOGUE\x10\x04\x1a%\n\x12\x42ytes_Performative\x12\x0f\n\x07\x63ontent\x18\x01 \x01(\x0c\x1a\x85\x02\n\x12\x45rror_Performative\x12H\n\nerror_code\x18\x01 \x01(\x0b\x32\x34.aea.fetchai.default.v1_0_0.DefaultMessage.ErrorCode\x12\x11\n\terror_msg\x18\x02 \x01(\t\x12`\n\nerror_data\x18\x03 \x03(\x0b\x32L.aea.fetchai.default.v1_0_0.DefaultMessage.Error_Performative.ErrorDataEntry\x1a\x30\n\x0e\x45rrorDataEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a\x12\n\x10\x45nd_PerformativeB\x0e\n\x0cperformativeb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "default_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _DEFAULTMESSAGE_ERROR_PERFORMATIVE_ERRORDATAENTRY._options = None
    _DEFAULTMESSAGE_ERROR_PERFORMATIVE_ERRORDATAENTRY._serialized_options = b"8\001"
    _globals["_DEFAULTMESSAGE"]._serialized_start = 46
    _globals["_DEFAULTMESSAGE"]._serialized_end = 868
    _globals["_DEFAULTMESSAGE_ERRORCODE"]._serialized_start = 301
    _globals["_DEFAULTMESSAGE_ERRORCODE"]._serialized_end = 529
    _globals["_DEFAULTMESSAGE_ERRORCODE_ERRORCODEENUM"]._serialized_start = 402
    _globals["_DEFAULTMESSAGE_ERRORCODE_ERRORCODEENUM"]._serialized_end = 529
    _globals["_DEFAULTMESSAGE_BYTES_PERFORMATIVE"]._serialized_start = 531
    _globals["_DEFAULTMESSAGE_BYTES_PERFORMATIVE"]._serialized_end = 568
    _globals["_DEFAULTMESSAGE_ERROR_PERFORMATIVE"]._serialized_start = 571
    _globals["_DEFAULTMESSAGE_ERROR_PERFORMATIVE"]._serialized_end = 832
    _globals["_DEFAULTMESSAGE_ERROR_PERFORMATIVE_ERRORDATAENTRY"]._serialized_start = (
        784
    )
    _globals["_DEFAULTMESSAGE_ERROR_PERFORMATIVE_ERRORDATAENTRY"]._serialized_end = 832
    _globals["_DEFAULTMESSAGE_END_PERFORMATIVE"]._serialized_start = 834
    _globals["_DEFAULTMESSAGE_END_PERFORMATIVE"]._serialized_end = 852
# @@protoc_insertion_point(module_scope)
