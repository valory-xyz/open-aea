# -*- coding: utf-8 -*-
# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: t_protocol_no_ct.proto
"""Generated protocol buffer code."""
from google.protobuf import descriptor as _descriptor
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder

# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\x16t_protocol_no_ct.proto\x12)aea.some_author.some_protocol_name.v1_0_0"\x8f\x39\n\x14TProtocolNoCtMessage\x12\x8f\x01\n\x1bperformative_empty_contents\x18\x05 \x01(\x0b\x32h.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Empty_Contents_PerformativeH\x00\x12w\n\x0fperformative_mt\x18\x06 \x01(\x0b\x32\\.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Mt_PerformativeH\x00\x12u\n\x0eperformative_o\x18\x07 \x01(\x0b\x32[.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_O_PerformativeH\x00\x12y\n\x10performative_pct\x18\x08 \x01(\x0b\x32].aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pct_PerformativeH\x00\x12y\n\x10performative_pmt\x18\t \x01(\x0b\x32].aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_PerformativeH\x00\x12w\n\x0fperformative_pt\x18\n \x01(\x0b\x32\\.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pt_PerformativeH\x00\x1a\x8c\x01\n\x1cPerformative_Pt_Performative\x12\x15\n\rcontent_bytes\x18\x01 \x01(\x0c\x12\x13\n\x0b\x63ontent_int\x18\x02 \x01(\x05\x12\x15\n\rcontent_float\x18\x03 \x01(\x01\x12\x14\n\x0c\x63ontent_bool\x18\x04 \x01(\x08\x12\x13\n\x0b\x63ontent_str\x18\x05 \x01(\t\x1a\xa8\x02\n\x1dPerformative_Pct_Performative\x12\x19\n\x11\x63ontent_set_bytes\x18\x01 \x03(\x0c\x12\x17\n\x0f\x63ontent_set_int\x18\x02 \x03(\x05\x12\x19\n\x11\x63ontent_set_float\x18\x03 \x03(\x01\x12\x18\n\x10\x63ontent_set_bool\x18\x04 \x03(\x08\x12\x17\n\x0f\x63ontent_set_str\x18\x05 \x03(\t\x12\x1a\n\x12\x63ontent_list_bytes\x18\x06 \x03(\x0c\x12\x18\n\x10\x63ontent_list_int\x18\x07 \x03(\x05\x12\x1a\n\x12\x63ontent_list_float\x18\x08 \x03(\x01\x12\x19\n\x11\x63ontent_list_bool\x18\t \x03(\x08\x12\x18\n\x10\x63ontent_list_str\x18\n \x03(\t\x1a\xfc\x18\n\x1dPerformative_Pmt_Performative\x12\x96\x01\n\x16\x63ontent_dict_int_bytes\x18\x01 \x03(\x0b\x32v.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictIntBytesEntry\x12\x92\x01\n\x14\x63ontent_dict_int_int\x18\x02 \x03(\x0b\x32t.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictIntIntEntry\x12\x96\x01\n\x16\x63ontent_dict_int_float\x18\x03 \x03(\x0b\x32v.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictIntFloatEntry\x12\x94\x01\n\x15\x63ontent_dict_int_bool\x18\x04 \x03(\x0b\x32u.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictIntBoolEntry\x12\x92\x01\n\x14\x63ontent_dict_int_str\x18\x05 \x03(\x0b\x32t.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictIntStrEntry\x12\x98\x01\n\x17\x63ontent_dict_bool_bytes\x18\x06 \x03(\x0b\x32w.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictBoolBytesEntry\x12\x94\x01\n\x15\x63ontent_dict_bool_int\x18\x07 \x03(\x0b\x32u.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictBoolIntEntry\x12\x98\x01\n\x17\x63ontent_dict_bool_float\x18\x08 \x03(\x0b\x32w.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictBoolFloatEntry\x12\x96\x01\n\x16\x63ontent_dict_bool_bool\x18\t \x03(\x0b\x32v.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictBoolBoolEntry\x12\x94\x01\n\x15\x63ontent_dict_bool_str\x18\n \x03(\x0b\x32u.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictBoolStrEntry\x12\x96\x01\n\x16\x63ontent_dict_str_bytes\x18\x0b \x03(\x0b\x32v.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictStrBytesEntry\x12\x92\x01\n\x14\x63ontent_dict_str_int\x18\x0c \x03(\x0b\x32t.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictStrIntEntry\x12\x96\x01\n\x16\x63ontent_dict_str_float\x18\r \x03(\x0b\x32v.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictStrFloatEntry\x12\x94\x01\n\x15\x63ontent_dict_str_bool\x18\x0e \x03(\x0b\x32u.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictStrBoolEntry\x12\x92\x01\n\x14\x63ontent_dict_str_str\x18\x0f \x03(\x0b\x32t.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Pmt_Performative.ContentDictStrStrEntry\x1a:\n\x18\x43ontentDictIntBytesEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a\x38\n\x16\x43ontentDictIntIntEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a:\n\x18\x43ontentDictIntFloatEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a\x39\n\x17\x43ontentDictIntBoolEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a\x38\n\x16\x43ontentDictIntStrEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a;\n\x19\x43ontentDictBoolBytesEntry\x12\x0b\n\x03key\x18\x01 \x01(\x08\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a\x39\n\x17\x43ontentDictBoolIntEntry\x12\x0b\n\x03key\x18\x01 \x01(\x08\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a;\n\x19\x43ontentDictBoolFloatEntry\x12\x0b\n\x03key\x18\x01 \x01(\x08\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a:\n\x18\x43ontentDictBoolBoolEntry\x12\x0b\n\x03key\x18\x01 \x01(\x08\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a\x39\n\x17\x43ontentDictBoolStrEntry\x12\x0b\n\x03key\x18\x01 \x01(\x08\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a:\n\x18\x43ontentDictStrBytesEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a\x38\n\x16\x43ontentDictStrIntEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a:\n\x18\x43ontentDictStrFloatEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1a\x39\n\x17\x43ontentDictStrBoolEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x08:\x02\x38\x01\x1a\x38\n\x16\x43ontentDictStrStrEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\t:\x02\x38\x01\x1a\xc1\x12\n\x1cPerformative_Mt_Performative\x12"\n\x1a\x63ontent_union_1_type_bytes\x18\x01 \x01(\x0c\x12)\n!content_union_1_type_bytes_is_set\x18\x02 \x01(\x08\x12 \n\x18\x63ontent_union_1_type_int\x18\x03 \x01(\x05\x12\'\n\x1f\x63ontent_union_1_type_int_is_set\x18\x04 \x01(\x08\x12"\n\x1a\x63ontent_union_1_type_float\x18\x05 \x01(\x01\x12)\n!content_union_1_type_float_is_set\x18\x06 \x01(\x08\x12!\n\x19\x63ontent_union_1_type_bool\x18\x07 \x01(\x08\x12(\n content_union_1_type_bool_is_set\x18\x08 \x01(\x08\x12 \n\x18\x63ontent_union_1_type_str\x18\t \x01(\t\x12\'\n\x1f\x63ontent_union_1_type_str_is_set\x18\n \x01(\x08\x12\'\n\x1f\x63ontent_union_1_type_set_of_int\x18\x0b \x03(\x05\x12.\n&content_union_1_type_set_of_int_is_set\x18\x0c \x01(\x08\x12)\n!content_union_1_type_list_of_bool\x18\r \x03(\x08\x12\x30\n(content_union_1_type_list_of_bool_is_set\x18\x0e \x01(\x08\x12\xad\x01\n$content_union_1_type_dict_of_str_int\x18\x0f \x03(\x0b\x32\x7f.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Mt_Performative.ContentUnion1TypeDictOfStrIntEntry\x12\x33\n+content_union_1_type_dict_of_str_int_is_set\x18\x10 \x01(\x08\x12)\n!content_union_2_type_set_of_bytes\x18\x11 \x03(\x0c\x12\x30\n(content_union_2_type_set_of_bytes_is_set\x18\x12 \x01(\x08\x12\'\n\x1f\x63ontent_union_2_type_set_of_int\x18\x13 \x03(\x05\x12.\n&content_union_2_type_set_of_int_is_set\x18\x14 \x01(\x08\x12\'\n\x1f\x63ontent_union_2_type_set_of_str\x18\x15 \x03(\t\x12.\n&content_union_2_type_set_of_str_is_set\x18\x16 \x01(\x08\x12*\n"content_union_2_type_list_of_float\x18\x17 \x03(\x01\x12\x31\n)content_union_2_type_list_of_float_is_set\x18\x18 \x01(\x08\x12)\n!content_union_2_type_list_of_bool\x18\x19 \x03(\x08\x12\x30\n(content_union_2_type_list_of_bool_is_set\x18\x1a \x01(\x08\x12*\n"content_union_2_type_list_of_bytes\x18\x1b \x03(\x0c\x12\x31\n)content_union_2_type_list_of_bytes_is_set\x18\x1c \x01(\x08\x12\xad\x01\n$content_union_2_type_dict_of_str_int\x18\x1d \x03(\x0b\x32\x7f.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Mt_Performative.ContentUnion2TypeDictOfStrIntEntry\x12\x33\n+content_union_2_type_dict_of_str_int_is_set\x18\x1e \x01(\x08\x12\xb2\x01\n&content_union_2_type_dict_of_int_float\x18\x1f \x03(\x0b\x32\x81\x01.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Mt_Performative.ContentUnion2TypeDictOfIntFloatEntry\x12\x35\n-content_union_2_type_dict_of_int_float_is_set\x18  \x01(\x08\x12\xb4\x01\n\'content_union_2_type_dict_of_bool_bytes\x18! \x03(\x0b\x32\x82\x01.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_Mt_Performative.ContentUnion2TypeDictOfBoolBytesEntry\x12\x36\n.content_union_2_type_dict_of_bool_bytes_is_set\x18" \x01(\x08\x1a\x44\n"ContentUnion1TypeDictOfStrIntEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x44\n"ContentUnion2TypeDictOfStrIntEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a\x46\n$ContentUnion2TypeDictOfIntFloatEntry\x12\x0b\n\x03key\x18\x01 \x01(\x05\x12\r\n\x05value\x18\x02 \x01(\x01:\x02\x38\x01\x1aG\n%ContentUnion2TypeDictOfBoolBytesEntry\x12\x0b\n\x03key\x18\x01 \x01(\x08\x12\r\n\x05value\x18\x02 \x01(\x0c:\x02\x38\x01\x1a\xcc\x03\n\x1bPerformative_O_Performative\x12\x16\n\x0e\x63ontent_o_bool\x18\x01 \x01(\x08\x12\x1d\n\x15\x63ontent_o_bool_is_set\x18\x02 \x01(\x08\x12\x19\n\x11\x63ontent_o_set_int\x18\x03 \x03(\x05\x12 \n\x18\x63ontent_o_set_int_is_set\x18\x04 \x01(\x08\x12\x1c\n\x14\x63ontent_o_list_bytes\x18\x05 \x03(\x0c\x12#\n\x1b\x63ontent_o_list_bytes_is_set\x18\x06 \x01(\x08\x12\x93\x01\n\x16\x63ontent_o_dict_str_int\x18\x07 \x03(\x0b\x32s.aea.some_author.some_protocol_name.v1_0_0.TProtocolNoCtMessage.Performative_O_Performative.ContentODictStrIntEntry\x12%\n\x1d\x63ontent_o_dict_str_int_is_set\x18\x08 \x01(\x08\x1a\x39\n\x17\x43ontentODictStrIntEntry\x12\x0b\n\x03key\x18\x01 \x01(\t\x12\r\n\x05value\x18\x02 \x01(\x05:\x02\x38\x01\x1a*\n(Performative_Empty_Contents_PerformativeB\x0e\n\x0cperformativeb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, "t_protocol_no_ct_pb2", _globals)
if _descriptor._USE_C_DESCRIPTORS == False:
    DESCRIPTOR._options = None
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBYTESENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBYTESENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTINTENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTINTENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTFLOATENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTFLOATENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBOOLENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBOOLENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTSTRENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTSTRENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBYTESENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBYTESENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLINTENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLINTENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLFLOATENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLFLOATENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBOOLENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBOOLENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLSTRENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLSTRENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBYTESENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBYTESENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRINTENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRINTENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRFLOATENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRFLOATENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBOOLENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBOOLENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRSTRENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRSTRENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION1TYPEDICTOFSTRINTENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION1TYPEDICTOFSTRINTENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFSTRINTENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFSTRINTENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFINTFLOATENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFINTFLOATENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFBOOLBYTESENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFBOOLBYTESENTRY._serialized_options = (
        b"8\001"
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_O_PERFORMATIVE_CONTENTODICTSTRINTENTRY._options = (
        None
    )
    _TPROTOCOLNOCTMESSAGE_PERFORMATIVE_O_PERFORMATIVE_CONTENTODICTSTRINTENTRY._serialized_options = (
        b"8\001"
    )
    _globals["_TPROTOCOLNOCTMESSAGE"]._serialized_start = 70
    _globals["_TPROTOCOLNOCTMESSAGE"]._serialized_end = 7381
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PT_PERFORMATIVE"]._serialized_start = (
        848
    )
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PT_PERFORMATIVE"]._serialized_end = 988
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PCT_PERFORMATIVE"
    ]._serialized_start = 991
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PCT_PERFORMATIVE"]._serialized_end = (
        1287
    )
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE"
    ]._serialized_start = 1290
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE"]._serialized_end = (
        4486
    )
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBYTESENTRY"
    ]._serialized_start = 3598
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBYTESENTRY"
    ]._serialized_end = 3656
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTINTENTRY"
    ]._serialized_start = 3658
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTINTENTRY"
    ]._serialized_end = 3714
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTFLOATENTRY"
    ]._serialized_start = 3716
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTFLOATENTRY"
    ]._serialized_end = 3774
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBOOLENTRY"
    ]._serialized_start = 3776
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTBOOLENTRY"
    ]._serialized_end = 3833
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTSTRENTRY"
    ]._serialized_start = 3835
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTINTSTRENTRY"
    ]._serialized_end = 3891
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBYTESENTRY"
    ]._serialized_start = 3893
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBYTESENTRY"
    ]._serialized_end = 3952
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLINTENTRY"
    ]._serialized_start = 3954
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLINTENTRY"
    ]._serialized_end = 4011
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLFLOATENTRY"
    ]._serialized_start = 4013
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLFLOATENTRY"
    ]._serialized_end = 4072
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBOOLENTRY"
    ]._serialized_start = 4074
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLBOOLENTRY"
    ]._serialized_end = 4132
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLSTRENTRY"
    ]._serialized_start = 4134
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTBOOLSTRENTRY"
    ]._serialized_end = 4191
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBYTESENTRY"
    ]._serialized_start = 4193
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBYTESENTRY"
    ]._serialized_end = 4251
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRINTENTRY"
    ]._serialized_start = 4253
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRINTENTRY"
    ]._serialized_end = 4309
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRFLOATENTRY"
    ]._serialized_start = 4311
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRFLOATENTRY"
    ]._serialized_end = 4369
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBOOLENTRY"
    ]._serialized_start = 4371
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRBOOLENTRY"
    ]._serialized_end = 4428
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRSTRENTRY"
    ]._serialized_start = 4430
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_PMT_PERFORMATIVE_CONTENTDICTSTRSTRENTRY"
    ]._serialized_end = 4486
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE"]._serialized_start = (
        4489
    )
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE"]._serialized_end = (
        6858
    )
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION1TYPEDICTOFSTRINTENTRY"
    ]._serialized_start = 6575
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION1TYPEDICTOFSTRINTENTRY"
    ]._serialized_end = 6643
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFSTRINTENTRY"
    ]._serialized_start = 6645
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFSTRINTENTRY"
    ]._serialized_end = 6713
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFINTFLOATENTRY"
    ]._serialized_start = 6715
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFINTFLOATENTRY"
    ]._serialized_end = 6785
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFBOOLBYTESENTRY"
    ]._serialized_start = 6787
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_MT_PERFORMATIVE_CONTENTUNION2TYPEDICTOFBOOLBYTESENTRY"
    ]._serialized_end = 6858
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_O_PERFORMATIVE"]._serialized_start = (
        6861
    )
    _globals["_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_O_PERFORMATIVE"]._serialized_end = 7321
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_O_PERFORMATIVE_CONTENTODICTSTRINTENTRY"
    ]._serialized_start = 7264
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_O_PERFORMATIVE_CONTENTODICTSTRINTENTRY"
    ]._serialized_end = 7321
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_EMPTY_CONTENTS_PERFORMATIVE"
    ]._serialized_start = 7323
    _globals[
        "_TPROTOCOLNOCTMESSAGE_PERFORMATIVE_EMPTY_CONTENTS_PERFORMATIVE"
    ]._serialized_end = 7365
# @@protoc_insertion_point(module_scope)
