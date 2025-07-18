# Test Protocol With No Custom Types

## Specification

```yaml
---
name: t_protocol_no_ct
author: fetchai
version: 0.1.0
license: Apache-2.0
aea_version: '>=2.0.0, <3.0.0'
protocol_specification_id: some_author/some_protocol_name:1.0.0
description: 'A protocol for testing purposes.'
speech_acts:
  performative_pt:
    content_bytes: pt:bytes
    content_int: pt:int
    content_float: pt:float
    content_bool: pt:bool
    content_str: pt:str
  performative_pct:
#    content_set_ct: pt:set[ct:DataModel] # custom type inside of set, list, and dict isn't allowed.
    content_set_bytes: pt:set[pt:bytes]
    content_set_int: pt:set[pt:int]
    content_set_float: pt:set[pt:float]
    content_set_bool: pt:set[pt:bool]
    content_set_str: pt:set[pt:str]
#    content_list_ct: pt:list[ct:DataModel] # custom type inside of set, list, and dict isn't allowed.
    content_list_bytes: pt:list[pt:bytes]
    content_list_int: pt:list[pt:int]
    content_list_float: pt:list[pt:float]
    content_list_bool: pt:list[pt:bool]
    content_list_str: pt:list[pt:str]
  performative_pmt:
#    custom type inside of set, list, and dict isn't allowed.
#    content_dict_int_ct: pt:dict[pt:int, ct:DataModel]
#    content_dict_ct_ct: pt:dict[ct:DataModel, ct:DataModel]
#    content_dict_ct_bool: pt:dict[ct:DataModel, pt:bool]
#    invalid in protobuf (key in map<X, Y> cannot be 'bytes', 'float', 'double', 'message')
#    content_dict_bytes_bytes: pt:dict[pt:bytes, pt:bytes]
#    content_dict_bytes_int: pt:dict[pt:bytes, pt:int]
#    content_dict_bytes_float: pt:dict[pt:bytes, pt:float]
#    content_dict_bytes_bool: pt:dict[pt:bytes, pt:bool]
#    content_dict_bytes_str: pt:dict[pt:bytes, pt:str]
    content_dict_int_bytes: pt:dict[pt:int, pt:bytes]
    content_dict_int_int: pt:dict[pt:int, pt:int]
    content_dict_int_float: pt:dict[pt:int, pt:float]
    content_dict_int_bool: pt:dict[pt:int, pt:bool]
    content_dict_int_str: pt:dict[pt:int, pt:str]
#    invalid in protobuf (key in map<X, Y> cannot be 'bytes', 'float', 'double', 'message')
#    content_dict_float_bytes: pt:dict[pt:float, pt:bytes]
#    content_dict_float_int: pt:dict[pt:float, pt:int]
#    content_dict_float_float: pt:dict[pt:float, pt:float]
#    content_dict_float_bool: pt:dict[pt:float, pt:bool]
#    content_dict_float_str: pt:dict[pt:float, pt:str]
    content_dict_bool_bytes: pt:dict[pt:bool, pt:bytes]
    content_dict_bool_int: pt:dict[pt:bool, pt:int]
    content_dict_bool_float: pt:dict[pt:bool, pt:float]
    content_dict_bool_bool: pt:dict[pt:bool, pt:bool]
    content_dict_bool_str: pt:dict[pt:bool, pt:str]
    content_dict_str_bytes: pt:dict[pt:str, pt:bytes]
    content_dict_str_int: pt:dict[pt:str, pt:int]
    content_dict_str_float: pt:dict[pt:str, pt:float]
    content_dict_str_bool: pt:dict[pt:str, pt:bool]
    content_dict_str_str: pt:dict[pt:str, pt:str]
  performative_mt:
    content_union_1: pt:union[pt:bytes, pt:int, pt:float, pt:bool, pt:str, pt:set[pt:int], pt:list[pt:bool], pt:dict[pt:str, pt:int]]
    content_union_2: pt:union[pt:set[pt:bytes], pt:set[pt:int], pt:set[pt:str], pt:list[pt:float], pt:list[pt:bool], pt:list[pt:bytes], pt:dict[pt:str, pt:int], pt:dict[pt:int, pt:float], pt:dict[pt:bool, pt:bytes]]
  performative_o:
    content_o_bool: pt:optional[pt:bool]
    content_o_set_int: pt:optional[pt:set[pt:int]]
    content_o_list_bytes: pt:optional[pt:list[pt:bytes]]
    content_o_dict_str_int: pt:optional[pt:dict[pt:str, pt:int]]
#    union does not work properly in the generator
#    content_o_union: pt:optional[pt:union[pt:str, pt:dict[pt:str,pt:int], pt:set[pt:int], pt:set[pt:bytes], pt:list[pt:bool], pt:dict[pt:str, pt:float]]]
  performative_empty_contents: {}
...
---
...
---
initiation: [performative_pt]
reply:
  performative_pt: [performative_pt, performative_pct, performative_pmt]
  performative_pct: [performative_mt, performative_o]
  performative_pmt: [performative_mt, performative_o]
  performative_mt: []
  performative_o: []
  performative_empty_contents: [performative_empty_contents]
termination: [performative_mt, performative_o]
roles: {role_1, role_2}
end_states: [end_state_1, end_state_2, end_state_3]
keep_terminal_state_dialogues: true
...
```

## Links
