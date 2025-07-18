# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: oef_search.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x10oef_search.proto\x12\x1d\x61\x65\x61.fetchai.oef_search.v1_0_0"\x89\r\n\x10OefSearchMessage\x12[\n\toef_error\x18\x05 \x01(\x0b\x32\x46.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Oef_Error_PerformativeH\x00\x12i\n\x10register_service\x18\x06 \x01(\x0b\x32M.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Register_Service_PerformativeH\x00\x12\x63\n\rsearch_result\x18\x07 \x01(\x0b\x32J.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Search_Result_PerformativeH\x00\x12g\n\x0fsearch_services\x18\x08 \x01(\x0b\x32L.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Search_Services_PerformativeH\x00\x12W\n\x07success\x18\t \x01(\x0b\x32\x44.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Success_PerformativeH\x00\x12m\n\x12unregister_service\x18\n \x01(\x0b\x32O.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Unregister_Service_PerformativeH\x00\x1a!\n\nAgentsInfo\x12\x13\n\x0b\x61gents_info\x18\x01 \x01(\x0c\x1a(\n\x0b\x44\x65scription\x12\x19\n\x11\x64\x65scription_bytes\x18\x01 \x01(\x0c\x1a\xdb\x01\n\x11OefErrorOperation\x12\x61\n\toef_error\x18\x01 \x01(\x0e\x32N.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.OefErrorOperation.OefErrorEnum"c\n\x0cOefErrorEnum\x12\x14\n\x10REGISTER_SERVICE\x10\x00\x12\x16\n\x12UNREGISTER_SERVICE\x10\x01\x12\x13\n\x0fSEARCH_SERVICES\x10\x02\x12\x10\n\x0cSEND_MESSAGE\x10\x03\x1a\x1c\n\x05Query\x12\x13\n\x0bquery_bytes\x18\x01 \x01(\x0c\x1ay\n\x1dRegister_Service_Performative\x12X\n\x13service_description\x18\x01 \x01(\x0b\x32;.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Description\x1a{\n\x1fUnregister_Service_Performative\x12X\n\x13service_description\x18\x01 \x01(\x0b\x32;.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Description\x1a\x64\n\x1cSearch_Services_Performative\x12\x44\n\x05query\x18\x01 \x01(\x0b\x32\x35.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.Query\x1a}\n\x1aSearch_Result_Performative\x12\x0e\n\x06\x61gents\x18\x01 \x03(\t\x12O\n\x0b\x61gents_info\x18\x02 \x01(\x0b\x32:.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.AgentsInfo\x1ag\n\x14Success_Performative\x12O\n\x0b\x61gents_info\x18\x01 \x01(\x0b\x32:.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.AgentsInfo\x1ax\n\x16Oef_Error_Performative\x12^\n\x13oef_error_operation\x18\x01 \x01(\x0b\x32\x41.aea.fetchai.oef_search.v1_0_0.OefSearchMessage.OefErrorOperationB\x0e\n\x0cperformativeb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "oef_search_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _globals["_OEFSEARCHMESSAGE"]._serialized_start = 52
    _globals["_OEFSEARCHMESSAGE"]._serialized_end = 1725
    _globals["_OEFSEARCHMESSAGE_AGENTSINFO"]._serialized_start = 678
    _globals["_OEFSEARCHMESSAGE_AGENTSINFO"]._serialized_end = 711
    _globals["_OEFSEARCHMESSAGE_DESCRIPTION"]._serialized_start = 713
    _globals["_OEFSEARCHMESSAGE_DESCRIPTION"]._serialized_end = 753
    _globals["_OEFSEARCHMESSAGE_OEFERROROPERATION"]._serialized_start = 756
    _globals["_OEFSEARCHMESSAGE_OEFERROROPERATION"]._serialized_end = 975
    _globals["_OEFSEARCHMESSAGE_OEFERROROPERATION_OEFERRORENUM"]._serialized_start = 876
    _globals["_OEFSEARCHMESSAGE_OEFERROROPERATION_OEFERRORENUM"]._serialized_end = 975
    _globals["_OEFSEARCHMESSAGE_QUERY"]._serialized_start = 977
    _globals["_OEFSEARCHMESSAGE_QUERY"]._serialized_end = 1005
    _globals["_OEFSEARCHMESSAGE_REGISTER_SERVICE_PERFORMATIVE"]._serialized_start = 1007
    _globals["_OEFSEARCHMESSAGE_REGISTER_SERVICE_PERFORMATIVE"]._serialized_end = 1128
    _globals["_OEFSEARCHMESSAGE_UNREGISTER_SERVICE_PERFORMATIVE"]._serialized_start = (
        1130
    )
    _globals["_OEFSEARCHMESSAGE_UNREGISTER_SERVICE_PERFORMATIVE"]._serialized_end = 1253
    _globals["_OEFSEARCHMESSAGE_SEARCH_SERVICES_PERFORMATIVE"]._serialized_start = 1255
    _globals["_OEFSEARCHMESSAGE_SEARCH_SERVICES_PERFORMATIVE"]._serialized_end = 1355
    _globals["_OEFSEARCHMESSAGE_SEARCH_RESULT_PERFORMATIVE"]._serialized_start = 1357
    _globals["_OEFSEARCHMESSAGE_SEARCH_RESULT_PERFORMATIVE"]._serialized_end = 1482
    _globals["_OEFSEARCHMESSAGE_SUCCESS_PERFORMATIVE"]._serialized_start = 1484
    _globals["_OEFSEARCHMESSAGE_SUCCESS_PERFORMATIVE"]._serialized_end = 1587
    _globals["_OEFSEARCHMESSAGE_OEF_ERROR_PERFORMATIVE"]._serialized_start = 1589
    _globals["_OEFSEARCHMESSAGE_OEF_ERROR_PERFORMATIVE"]._serialized_end = 1709
# @@protoc_insertion_point(module_scope)
