# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2024 Valory AG
#   Copyright 2018-2019 Fetch.AI Limited
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
#
# ------------------------------------------------------------------------------

"""Implementation of the environment variables support."""
import json
import re
from collections.abc import Mapping as MappingType
from typing import Any, Dict, List, Mapping, Optional, Tuple, Union, cast

from aea.configurations.data_types import PublicId
from aea.helpers.constants import (
    FALSE_EQUIVALENTS,
    FROM_STRING_TO_TYPE,
    JSON_TYPES,
    NULL_EQUIVALENTS,
)


ENV_VARIABLE_RE = re.compile(r"^\$\{(([A-Z0-9_]+):?)?([a-z]+)?(:(.+))?}$")
MODELS = "models"
ARGS = "args"
ARGS_LEVEL_FROM_MODELS = 2
ARG_LEVEL_FROM_MODELS = ARGS_LEVEL_FROM_MODELS + 1
RESTRICTION_EXCEPTIONS = frozenset({"setup", "genesis_config"})


def is_env_variable(value: Any) -> bool:
    """Check is variable string with env variable pattern."""
    return isinstance(value, str) and bool(ENV_VARIABLE_RE.match(value))


def restrict_model_args(export_path: List[str]) -> Tuple[List[str], List[str]]:
    """Do not allow more levels than one for a model's argument."""
    restricted = []
    result = []
    for i, current_path in enumerate(export_path):
        result.append(current_path)
        args_level = i + ARGS_LEVEL_FROM_MODELS
        arg_level = i + ARG_LEVEL_FROM_MODELS
        if (
            current_path == MODELS
            and arg_level < len(export_path)
            and export_path[args_level] == ARGS
            and export_path[arg_level] not in RESTRICTION_EXCEPTIONS
        ):
            # do not allow more levels than one for a model's argument
            arg_content_level = arg_level + 1
            result.extend(export_path[i + 1 : arg_content_level])
            # store the restricted part of the path
            for j in range(arg_content_level, len(export_path)):
                restricted.append(export_path[j])
            break
    return restricted, result


def export_path_to_env_var_string(export_path: List[str]) -> Tuple[List[str], str]:
    """Convert export path to environment variable string."""
    restricted, export_path = restrict_model_args(export_path)
    env_var_string = "_".join(map(str, export_path))
    return restricted, env_var_string.upper()


NotSet = object()


def parse_list(var_prefix: str, env_variables: dict) -> str:
    """Parse list object."""
    values = {}
    _vars = list(filter(lambda x: x.startswith(var_prefix), env_variables.keys()))
    for var in _vars:
        _, idx, *sub_var = var.replace(var_prefix, "").split("_")
        if len(sub_var) > 0:
            values[idx] = json.loads(
                parse_list(
                    var_prefix=f"{var_prefix}_{idx}",
                    env_variables=env_variables,
                )
            )
            continue
        try:
            values[idx] = json.loads(str(env_variables[var]))
        except (json.JSONDecodeError, ValueError):
            values[idx] = env_variables[var]
    if all(map(lambda x: isinstance(json.loads(x), int), values.keys())):
        return json.dumps([values[idx] for idx in sorted(values)])
    return json.dumps({json.loads(key): val for key, val in values.items()})


def replace_with_env_var(
    value: str,
    env_variables: dict,
    default_value: Any = NotSet,
    default_var_name: Optional[str] = None,
) -> JSON_TYPES:
    """Replace env var with value."""
    result = ENV_VARIABLE_RE.match(value)

    if not result:
        return value

    _, var_name, type_str, _, default = result.groups()
    if var_name is None and default_var_name is not None:
        var_name = default_var_name

    if var_name in env_variables:
        var_value = env_variables[var_name]
    elif type_str == "list":
        var_value = parse_list(
            var_prefix=var_name,
            env_variables=env_variables,
        )
        var_value = (default or var_value) if var_value == "[]" else var_value
    elif default is not None:
        var_value = default
    elif default_value is not NotSet:
        var_value = default_value
    else:
        raise ValueError(
            f"`{var_name}` not found in env variables and no default value set! Please ensure a .env file is provided."
        )

    if type_str is not None:
        var_value = convert_value_str_to_type(var_value, type_str)
    return var_value


def apply_env_variables(
    data: Union[Dict, List[Dict]],
    env_variables: Mapping[str, Any],
    path: Optional[List[str]] = None,
    default_value: Any = NotSet,
) -> JSON_TYPES:
    """Create new resulting dict with env variables applied."""
    path = path or []

    if isinstance(data, (list, tuple)):
        result = []
        for i, obj in enumerate(data):
            result.append(
                apply_env_variables(
                    data=obj,
                    env_variables=env_variables,
                    path=[*path, str(i)],
                    default_value=default_value,
                )
            )
        return result

    if isinstance(data, MappingType):
        return {
            k: apply_env_variables(
                data=v,
                env_variables=env_variables,
                path=[*path, k],
                default_value=default_value,
            )
            for k, v in data.items()
        }

    if is_env_variable(data):
        return replace_with_env_var(
            data,
            env_variables,
            default_value,
            default_var_name=export_path_to_env_var_string(export_path=path)[1],
        )

    return data


def convert_value_str_to_type(value: str, type_str: str) -> JSON_TYPES:
    """Convert value by type name to native python type."""
    try:
        type_ = FROM_STRING_TO_TYPE[type_str]
        if type_ == bool:
            return value not in FALSE_EQUIVALENTS
        if type_ is None or value in NULL_EQUIVALENTS:
            return None
        if type_ in (dict, list):
            return json.loads(value)
        return type_(value)
    except (ValueError, json.decoder.JSONDecodeError):
        raise ValueError(f"Cannot convert string `{value}` to type `{type_.__name__}`")  # type: ignore
    except KeyError:
        raise KeyError(f"`{type_str}` is not a valid python data type")


def apply_env_variables_on_agent_config(
    data: List[Dict],
    env_variables: Mapping[str, Any],
) -> List[Dict]:
    """Create new resulting dict with env variables applied."""

    agent_config, *overrides = data
    agent_config_new = apply_env_variables(
        data=agent_config,
        env_variables=env_variables,
        path=[
            "agent",
        ],
    )

    overrides_new = []
    for component_config in overrides:
        component_name = PublicId.from_str(
            cast(str, component_config.get("public_id")),
        ).name
        component_type = cast(str, component_config.get("type"))
        new_component_config = cast(
            Dict,
            apply_env_variables(
                data=component_config,
                env_variables=env_variables,
                path=[
                    component_type,
                    component_name,
                ],
            ),
        )
        overrides_new.append(new_component_config)

    return [cast(Dict, agent_config_new), *overrides_new]


def is_strict_list(data: Union[List, Tuple]) -> bool:
    """
    Check if a data list is an strict list

    The data list contains a mapping object we need to process it as an
    object containing configurable parameters. For example

    cert_requests:
      - public_key: example_public_key

    This will get exported as `CONNECTION_NAME_CERT_REQUESTS_0_PUBLIC_KEY=example_public_key`

    Where as

    parameters:
     - hello
     - world

     will get exported as `SKILL_NAME_PARAMETERS=["hello", "world"]`

    :param data: Data list
    :return: Boolean specifying whether it's a strict list or not
    """
    is_strict = True
    for obj in data:
        if isinstance(obj, dict):
            return False
        if isinstance(obj, (list, tuple)):
            if not is_strict_list(data=obj):
                return False
    return is_strict


def list_to_nested_dict(lst: list, val: Any) -> dict:
    """Convert a list to a nested dict."""
    nested_dict = val
    for item in reversed(lst):
        nested_dict = {item: nested_dict}
    return nested_dict


def ensure_dict(dict_: Dict[str, Union[dict, str]]) -> dict:
    """Return the given dictionary converting any values which are json strings as dicts."""
    return {k: json.loads(v) for k, v in dict_.items() if isinstance(v, str)}


def ensure_json_content(dict_: dict) -> dict:
    """Return the given dictionary converting any nested dictionary values as json strings."""
    return {k: json.dumps(v) for k, v in dict_.items() if isinstance(v, dict)}


def merge_dicts(a: dict, b: dict) -> dict:
    """Merge two dictionaries."""
    # shallow copy of `a`
    merged = {**a}
    for key, value in b.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            # recursively merge nested dictionaries
            merged[key] = merge_dicts(merged[key], value)
        else:
            # if not a nested dictionary, just take the value from `b`
            merged[key] = value
    return merged


def generate_env_vars_recursively(
    data: Union[Dict, List],
    export_path: List[str],
) -> Dict:
    """Generate environment variables recursively."""
    env_var_dict: Dict[str, Any] = {}

    if isinstance(data, dict):
        for key, value in data.items():
            res = generate_env_vars_recursively(
                data=value,
                export_path=[*export_path, key],
            )
            if res:
                env_var = list(res.keys())[0]
                if env_var in env_var_dict:
                    dicts = (ensure_dict(dict_) for dict_ in (env_var_dict, res))
                    res = ensure_json_content(merge_dicts(*dicts))
            env_var_dict.update(res)
    elif isinstance(data, list):
        if is_strict_list(data=data):
            restricted, path = export_path_to_env_var_string(export_path=export_path)
            if restricted:
                env_var_dict[path] = json.dumps(list_to_nested_dict(restricted, data))
            else:
                env_var_dict[path] = json.dumps(data, separators=(",", ":"))
        else:
            for key, value in enumerate(data):
                res = generate_env_vars_recursively(
                    data=value,
                    export_path=[*export_path, key],
                )
                env_var_dict.update(res)
    else:
        restricted, path = export_path_to_env_var_string(export_path=export_path)
        if restricted:
            env_var_dict[path] = json.dumps(list_to_nested_dict(restricted, data))
        else:
            env_var_dict[path] = data

    return env_var_dict
