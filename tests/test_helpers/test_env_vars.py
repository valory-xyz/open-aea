# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2026 Valory AG
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
"""This module contains the tests for the helper module."""

import json
import re
from typing import List

import pytest

from aea.helpers.env_vars import (
    apply_env_variables,
    apply_env_variables_on_agent_config,
    convert_value_str_to_type,
    export_path_to_env_var_string,
    generate_env_vars_recursively,
    has_env_safe_keys,
    is_env_variable,
    is_strict_list,
    replace_with_env_var,
)


def test_is_env_variable():
    """Test is_env_variable."""
    assert is_env_variable("${TEST}")
    assert is_env_variable("${TEST:int}")
    assert is_env_variable("${TEST:int:12}")

    assert not is_env_variable("sdfsdf")


def test_apply_env_variables():
    """Test apply_env_variables"""
    assert apply_env_variables("${VAR}", {"VAR": "test"}) == "test"
    assert apply_env_variables("var", {"var": "test"}) == "var"
    assert apply_env_variables(["${VAR}"], {"VAR": "test"}) == ["test"]


def test_replace_with_env_var():
    """Test replace_with_env_var."""
    assert replace_with_env_var("${VAR:int:12}", {"VAR": "10"}) == 10
    assert replace_with_env_var("${VAR:int:12}", {}) == 12
    assert replace_with_env_var("${VAR}", {}, default_value=100) == 100

    assert replace_with_env_var("var", {}) == "var"


def test_failures() -> None:
    """Test failures."""

    with pytest.raises(
        ValueError,
        match=r"`VAR` not found in env variables and no default value set!",
    ):
        replace_with_env_var("${VAR}", {})

    with pytest.raises(KeyError, match="`var` is not a valid python data type"):
        replace_with_env_var("${VAR:var}", {"VAR": "some_value"})

    with pytest.raises(
        ValueError, match="Cannot convert string `some_value` to type `float`"
    ):
        replace_with_env_var("${VAR:float}", {"VAR": "some_value"})


def test_apply_none_with_env_var():
    """Test replace_with_env_var."""
    assert replace_with_env_var("${VAR:int:none}", {"VAR": "10"}) == 10
    assert replace_with_env_var("${VAR:int:none}", {}) is None


def test_convert_value_str_to_type():
    """Test convert_value_str_to_type."""
    assert convert_value_str_to_type("false", "bool") is False
    assert convert_value_str_to_type("True", "bool") is True
    assert convert_value_str_to_type("12", "int") == 12
    assert convert_value_str_to_type("1.1", "float") == 1.1
    assert convert_value_str_to_type("1sdfsdf2", "none") is None
    assert convert_value_str_to_type('{"a": 12}', "dict") == {"a": 12}
    assert convert_value_str_to_type("Null", "str") is None
    assert convert_value_str_to_type("none", "str") is None
    assert convert_value_str_to_type("null", "str") is None
    assert convert_value_str_to_type("None", "str") is None


@pytest.mark.parametrize(
    ("export_path", "var_string"),
    argvalues=[
        (["skill", "dummy", "models", "args"], "SKILL_DUMMY_MODELS_ARGS"),
        (
            ["skill", "dummy", "models", "args", "params"],
            "SKILL_DUMMY_MODELS_ARGS_PARAMS",
        ),
        (
            ["skill", "dummy", "models", "args", "params", "name"],
            "SKILL_DUMMY_MODELS_ARGS_PARAMS_NAME",
        ),
        (["connection", "dummy", "config", "host"], "CONNECTION_DUMMY_CONFIG_HOST"),
        ([0, "connection", "dummy"], "0_CONNECTION_DUMMY"),
        (["connection", 0, "dummy"], "CONNECTION_0_DUMMY"),
        (["connection", "dummy", 0], "CONNECTION_DUMMY_0"),
    ],
)
def test_env_var_string_generator(export_path: List[str], var_string: str) -> None:
    """Test `export_path_to_env_var_string` method"""

    assert export_path_to_env_var_string(export_path=export_path)[1] == var_string


@pytest.mark.parametrize(
    ("export_data", "template"),
    argvalues=[
        (
            {
                "dict": "Viraj",
            },
            {
                "dict": "${str}",
            },
        ),
        (
            {"list": [1, 2, 3]},
            {"list": "${list}"},
        ),
        (
            {
                "nested_dict": {
                    "dict": "Viraj",
                }
            },
            {
                "nested_dict": {
                    "dict": "${str}",
                },
            },
        ),
        (
            {"nested_list": [[1], [2], [3]]},
            {"nested_list": "${list}"},
        ),
        (
            {
                "nested_dict": {
                    "dict": "Viraj",
                    "list": [1, 2, 3],
                }
            },
            {
                "nested_dict": {
                    "dict": "${str}",
                    "list": "${list}",
                },
            },
        ),
        (
            {
                "nested_list": [
                    {
                        "dict": "hello",
                    },
                    {
                        "dict": "world",
                    },
                ]
            },
            {
                "nested_list": [
                    {"dict": "${str}"},
                    {"dict": "${str}"},
                ]
            },
        ),
        (
            {
                "stratagies_kwargs": [
                    ["bet_kelly_fraction", 0.25],
                    ["floor_balance", 500000000000000000],
                    [
                        "bet_amount_per_threshold",
                        {
                            "0.0": 0,
                            "0.1": 0,
                            "0.2": 0,
                            "0.3": 0,
                            "0.4": 0,
                            "0.5": 0,
                            "0.6": 60000000000000000,
                            "0.7": 90000000000000000,
                            "0.8": 100000000000000000,
                            "0.9": 1000000000000000000,
                            "1.0": 10000000000000000000,
                        },
                    ],
                ],
            },
            {
                "stratagies_kwargs": "${list:[]}",
            },
        ),
    ],
)
def test_match_export_parse_consistency(export_data, template) -> None:
    """Test to match export and parsing consistency with different data structures."""

    env_vars = generate_env_vars_recursively(
        export_data,
        export_path=[],
    )

    parsed_data = apply_env_variables(template, env_variables=env_vars)

    assert parsed_data == export_data


@pytest.mark.parametrize(
    ("template", "parsed"),
    argvalues=[
        (
            {"value": "${str:john}"},
            {"value": "john"},
        ),
        (
            {"value": "${int:3}"},
            {"value": 3},
        ),
        (
            {"value": "${bool:false}"},
            {"value": False},
        ),
        (
            {"value": '${list:["foo","bar"]}'},
            {"value": ["foo", "bar"]},
        ),
        (
            {"value": '${dict:{"foo":"bar"}}'},
            {"value": {"foo": "bar"}},
        ),
    ],
)
def test_parse_defaults(template, parsed) -> None:
    """Test default value parsing."""
    parsed_data = apply_env_variables(template, env_variables={})
    assert parsed_data == parsed


def test_apply_env_variables_on_agent_config():
    """Test apply_env_variables_on_agent_config function."""
    result = apply_env_variables_on_agent_config(
        [{"arg": "${VAR}"}, {"public_id": "fetchai/test:0.1.0", "arg": "${VAR}"}],
        {"VAR": 12},
    )
    assert result == [{"arg": 12}, {"arg": 12, "public_id": "fetchai/test:0.1.0"}]


def test_is_strict_list():
    """Test is_strict method."""
    assert is_strict_list([1, 2, 3])
    assert is_strict_list([1, 2, 3, [1, 2, 3]])
    assert not is_strict_list([1, 2, {}])
    assert not is_strict_list([1, 2, [[{}]]])
    assert not is_strict_list([(dict(hello="world"),)])


def test_has_env_safe_keys():
    """Test has_env_safe_keys method."""
    assert has_env_safe_keys({"timeout": 30, "retries": 5})
    assert has_env_safe_keys({"foo_bar": 1, "BAZ": 2, "_x": 3})
    assert has_env_safe_keys({})
    assert not has_env_safe_keys({"0.0": 0, "1.0": 100})
    assert not has_env_safe_keys({"foo-bar": 1})
    assert not has_env_safe_keys({"timeout": 30, "0.0": 0})
    assert not has_env_safe_keys({"1foo": 1})
    assert not has_env_safe_keys({1: "non-string-key"})


def test_generate_env_vars_safe_key_dict_flattens_per_key():
    """Safe-key dicts still flatten per key (unchanged behaviour)."""
    result = generate_env_vars_recursively(
        data={"timeout": 30, "retries": 5},
        export_path=["test", "foo"],
    )
    assert result == {
        "TEST_FOO_TIMEOUT": 30,
        "TEST_FOO_RETRIES": 5,
    }


def test_generate_env_vars_unsafe_key_dict_json_encodes_whole():
    """Dict with bash-unsafe keys becomes one JSON-encoded env var.

    Covers the trader case from open-autonomy issue #2243.
    """
    data = {
        "0.0": 0,
        "0.6": 60000000000000000,
        "1.0": 1000000000000000000,
    }
    result = generate_env_vars_recursively(
        data=data,
        export_path=["test", "foo", "bet_amount_per_threshold"],
    )
    assert result == {
        "TEST_FOO_BET_AMOUNT_PER_THRESHOLD": json.dumps(data, separators=(",", ":"))
    }
    bash_safe = re.compile(r"^[A-Z_][A-Z0-9_]*$")
    assert all(bash_safe.match(name) for name in result)


def test_generate_env_vars_mixed_key_dict_json_encodes_whole():
    """Mixed safe/unsafe keys also JSON-encode the whole dict."""
    data = {"timeout": 30, "0.0": 0}
    result = generate_env_vars_recursively(
        data=data,
        export_path=["test", "foo", "trading_config"],
    )
    assert result == {
        "TEST_FOO_TRADING_CONFIG": json.dumps(data, separators=(",", ":"))
    }


def test_generate_env_vars_unsafe_dict_inside_safe_dict_collapses_only_inner():
    """Unsafe keys collapse at their level; safe siblings still flatten per key."""
    data = {
        "bet_kelly_fraction": 1,
        "bet_amount_per_threshold": {
            "0.0": 0,
            "1.0": 1000000000000000000,
        },
    }
    result = generate_env_vars_recursively(
        data=data,
        export_path=["test", "foo", "strategies_kwargs"],
    )
    assert result["TEST_FOO_STRATEGIES_KWARGS_BET_KELLY_FRACTION"] == 1
    inner = result["TEST_FOO_STRATEGIES_KWARGS_BET_AMOUNT_PER_THRESHOLD"]
    assert json.loads(inner) == data["bet_amount_per_threshold"]


def test_generate_env_vars_empty_dict_returns_empty():
    """Empty dict is vacuously safe-keyed and emits no env vars."""
    result = generate_env_vars_recursively(data={}, export_path=["test", "foo"])
    assert result == {}


def test_generate_env_vars_unsafe_key_dict_under_models_args_uses_restricted_path():
    """Production path: unsafe-key dict nested under ``args/<arg>/...`` collapses correctly.

    Under the ``args`` level the framework restricts the env var name to the
    arg-level key (``strategies_kwargs`` here), nesting any deeper path keys
    (``bet_amount_per_threshold``) inside the JSON value. The unsafe-key
    branch must respect that restriction so trader-style overrides land in
    the same env var the per-key flatten would have collapsed to.
    """
    data = {
        "0.0": 0,
        "1.0": 1000000000000000000,
    }
    result = generate_env_vars_recursively(
        data=data,
        export_path=[
            "skill",
            "trader_abci",
            "models",
            "params",
            "args",
            "strategies_kwargs",
            "bet_amount_per_threshold",
        ],
    )
    assert result == {
        "SKILL_TRADER_ABCI_MODELS_PARAMS_ARGS_STRATEGIES_KWARGS": json.dumps(
            {"bet_amount_per_threshold": data}, separators=(",", ":")
        )
    }


def test_generate_env_vars_float_keys_normalize_to_strings():
    """PyYAML-parsed float keys travel through env vars as JSON strings.

    YAML allows `0.0: x` (unquoted) which loads as a Python float key.
    `has_env_safe_keys` rejects non-string keys, the dict gets
    JSON-encoded, and `json.dumps`/`json.loads` coerces float keys to
    strings. This is not a regression - the old per-key flatten would
    have produced bash-invalid `..._0.0` names anyway - but it is an
    intentional behaviour change. A consumer indexing `config[0.0]`
    after an env override would hit a `KeyError`; they must index by
    the stringified key.
    """
    data = {0.0: 0, 0.6: 60000000000000000, 1.0: 1000000000000000000}
    env_vars = generate_env_vars_recursively(
        data={"bet_amount_per_threshold": data},
        export_path=["skill", "trader_abci"],
    )
    decoded = json.loads(env_vars["SKILL_TRADER_ABCI_BET_AMOUNT_PER_THRESHOLD"])
    assert set(decoded.keys()) == {"0.0", "0.6", "1.0"}
    assert all(isinstance(k, str) for k in decoded)
    assert decoded["0.6"] == 60000000000000000


def test_generate_env_vars_restricted_collision_with_unsafe_dict_sibling():
    """Trader-style: restriction + collision + unsafe-key dict all combine.

    A safe-keyed `strategies_kwargs` under `models/.../args/` holds both
    a scalar sibling (`bet_kelly_fraction`) and an unsafe-key dict
    sibling (`bet_amount_per_threshold`). Both collapse to the same
    `..._STRATEGIES_KWARGS` env var via the `restricted` path and must
    fuse via the dict-iteration merge_dicts branch. Locks in the merge
    semantics so a refactor of the collision logic cannot silently drop
    either sibling.
    """
    inner = {"0.0": 0, "1.0": 1000000000000000000}
    models = {
        "params": {
            "args": {
                "strategies_kwargs": {
                    "bet_kelly_fraction": 1,
                    "bet_amount_per_threshold": inner,
                }
            }
        }
    }
    result = generate_env_vars_recursively(
        data=models, export_path=["skill", "trader_abci", "models"]
    )
    env_var = "SKILL_TRADER_ABCI_MODELS_PARAMS_ARGS_STRATEGIES_KWARGS"
    assert list(result.keys()) == [env_var]
    fused = json.loads(result[env_var])
    assert fused == {
        "bet_kelly_fraction": 1,
        "bet_amount_per_threshold": inner,
    }


def test_unsafe_key_dict_roundtrips_through_dict_template():
    """End-to-end: unsafe-key dict survives readback via ${dict:default}.

    The agent's effective config has a ${VAR:dict:default} placeholder.
    With env vars set, the placeholder must resolve to the produced dict,
    not silently fall back to the default.
    """
    data = {
        "0.0": 0,
        "0.6": 60000000000000000,
        "1.0": 1000000000000000000,
    }
    env_vars = generate_env_vars_recursively(
        data={"bet_amount_per_threshold": data},
        export_path=["skill", "trader_abci"],
    )
    fallback = {"only-if-env-missing": 1}
    placeholder = "${dict:" + json.dumps(fallback) + "}"
    template = {"bet_amount_per_threshold": placeholder}
    result = apply_env_variables(
        template, env_variables=env_vars, path=["skill", "trader_abci"]
    )
    assert result["bet_amount_per_threshold"] == data


def test_safe_key_numeric_strings_preserved_through_json_encode():
    """Numeric-looking string keys keep their exact form when JSON-encoded.

    Regression check for a latent bug in the pre-fix per-key flatten path:
    it round-tripped dict keys through ``json.loads`` which silently
    rewrote keys like ``"0.10"`` into ``"0.1"``. JSON-encoding the whole
    dict preserves keys verbatim.
    """
    data = {"0.0": 0, "0.10": 5, "1.0": 9}
    env_vars = generate_env_vars_recursively(
        data={"thresholds": data}, export_path=["skill", "x"]
    )
    encoded = env_vars["SKILL_X_THRESHOLDS"]
    decoded = json.loads(encoded)
    assert decoded == data
    assert set(decoded.keys()) == {"0.0", "0.10", "1.0"}
