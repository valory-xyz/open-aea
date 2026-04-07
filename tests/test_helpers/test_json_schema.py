# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
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

"""Tests for the inlined JSON schema validator."""

import json
from pathlib import Path
from typing import List

import pytest

from aea.helpers.json_schema import (
    Draft4Validator,
    RefResolver,
    ValidationError,
    extend,
    find_additional_properties,
)

# --- ValidationError ---


class TestValidationError:
    """Tests for ValidationError."""

    def test_message_and_path(self) -> None:
        """Test that ValidationError stores message and path."""
        err = ValidationError("bad value", path=["foo", "bar"])
        assert err.message == "bad value"
        assert list(err.path) == ["foo", "bar"]
        assert "bad value" in str(err)

    def test_empty_path(self) -> None:
        """Test ValidationError with no path."""
        err = ValidationError("missing")
        assert list(err.path) == []


# --- Type validation ---


class TestTypeValidation:
    """Tests for type keyword."""

    def test_string(self) -> None:
        """Test string type validation."""
        schema = {"type": "string"}
        Draft4Validator(schema).validate("hello")
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate(123)

    def test_integer(self) -> None:
        """Test integer type validation."""
        schema = {"type": "integer"}
        Draft4Validator(schema).validate(42)
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate("hello")

    def test_number(self) -> None:
        """Test number type validation."""
        schema = {"type": "number"}
        Draft4Validator(schema).validate(3.14)
        Draft4Validator(schema).validate(42)
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate("hello")

    def test_boolean(self) -> None:
        """Test boolean type validation."""
        schema = {"type": "boolean"}
        Draft4Validator(schema).validate(True)
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate(1)

    def test_null(self) -> None:
        """Test null type validation."""
        schema = {"type": "null"}
        Draft4Validator(schema).validate(None)
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate("")

    def test_array(self) -> None:
        """Test array type validation."""
        schema = {"type": "array"}
        Draft4Validator(schema).validate([1, 2, 3])
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate("not array")

    def test_object(self) -> None:
        """Test object type validation."""
        schema = {"type": "object"}
        Draft4Validator(schema).validate({"key": "value"})
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate([])

    def test_nullable_type(self) -> None:
        """Test type as list e.g. ["string", "null"]."""
        schema = {"type": ["string", "null"]}
        Draft4Validator(schema).validate("hello")
        Draft4Validator(schema).validate(None)
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate(123)


# --- Properties and required ---


class TestProperties:
    """Tests for properties and required keywords."""

    def test_properties(self) -> None:
        """Test properties validation."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}, "age": {"type": "integer"}},
        }
        Draft4Validator(schema).validate({"name": "Alice", "age": 30})
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate({"name": "Alice", "age": "thirty"})

    def test_required(self) -> None:
        """Test required fields."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "required": ["name"],
        }
        Draft4Validator(schema).validate({"name": "Alice"})
        with pytest.raises(ValidationError, match="required"):
            Draft4Validator(schema).validate({})

    def test_additional_properties_false(self) -> None:
        """Test additionalProperties: false."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": False,
        }
        Draft4Validator(schema).validate({"name": "Alice"})
        with pytest.raises(ValidationError, match="additional"):
            Draft4Validator(schema).validate({"name": "Alice", "extra": "bad"})

    def test_additional_properties_true(self) -> None:
        """Test additionalProperties: true (default)."""
        schema = {
            "type": "object",
            "properties": {"name": {"type": "string"}},
            "additionalProperties": True,
        }
        Draft4Validator(schema).validate({"name": "Alice", "extra": "ok"})

    def test_pattern_properties(self) -> None:
        """Test patternProperties validation."""
        schema = {
            "type": "object",
            "additionalProperties": False,
            "patternProperties": {"^x-": {"type": "string"}},
        }
        Draft4Validator(schema).validate({"x-custom": "val"})
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate({"x-custom": 123})
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate({"unknown": "val"})

    def test_find_additional_properties(self) -> None:
        """Test find_additional_properties helper."""
        schema = {
            "properties": {"name": {"type": "string"}},
            "patternProperties": {"^x-": {"type": "string"}},
        }
        instance = {"name": "Alice", "x-foo": "bar", "extra": "bad"}
        extras = list(find_additional_properties(instance, schema))
        assert extras == ["extra"]

    def test_property_names(self) -> None:
        """Test propertyNames validation."""
        schema = {
            "type": "object",
            "propertyNames": {"pattern": r"^[a-z][a-z0-9_]+\/[a-z_0-9]+:\d\.\d\.\d$"},
        }
        Draft4Validator(schema).validate({"author/package:0.1.0": "hash"})
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate({"INVALID KEY": "hash"})


# --- Array validation ---


class TestArrayValidation:
    """Tests for array-related keywords."""

    def test_items(self) -> None:
        """Test items validation."""
        schema = {"type": "array", "items": {"type": "integer"}}
        Draft4Validator(schema).validate([1, 2, 3])
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate([1, "two", 3])

    def test_unique_items(self) -> None:
        """Test uniqueItems."""
        schema = {"type": "array", "uniqueItems": True}
        Draft4Validator(schema).validate([1, 2, 3])
        with pytest.raises(ValidationError, match="unique"):
            Draft4Validator(schema).validate([1, 2, 2])


# --- Enum, pattern, minimum ---


class TestScalarConstraints:
    """Tests for enum, pattern, minimum keywords."""

    def test_enum(self) -> None:
        """Test enum validation."""
        schema = {"enum": ["a", "b", "c"]}
        Draft4Validator(schema).validate("a")
        with pytest.raises(ValidationError, match="enum"):
            Draft4Validator(schema).validate("d")

    def test_pattern(self) -> None:
        """Test pattern validation."""
        schema = {"type": "string", "pattern": "^[a-z]+$"}
        Draft4Validator(schema).validate("abc")
        with pytest.raises(ValidationError, match="pattern"):
            Draft4Validator(schema).validate("ABC")

    def test_minimum(self) -> None:
        """Test minimum validation."""
        schema = {"type": "number", "minimum": 0}
        Draft4Validator(schema).validate(0)
        Draft4Validator(schema).validate(5)
        with pytest.raises(ValidationError, match="minimum"):
            Draft4Validator(schema).validate(-1)


# --- oneOf ---


class TestOneOf:
    """Tests for oneOf keyword."""

    def test_one_match(self) -> None:
        """Test oneOf with exactly one match."""
        schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
        Draft4Validator(schema).validate("hello")
        Draft4Validator(schema).validate(42)

    def test_no_match(self) -> None:
        """Test oneOf with no matches."""
        schema = {"oneOf": [{"type": "string"}, {"type": "integer"}]}
        with pytest.raises(ValidationError, match="oneOf"):
            Draft4Validator(schema).validate([1, 2])


# --- $ref ---


class TestRef:
    """Tests for $ref resolution."""

    def test_internal_ref(self) -> None:
        """Test internal #/definitions/ reference."""
        schema = {
            "type": "object",
            "properties": {"name": {"$ref": "#/definitions/name_def"}},
            "definitions": {"name_def": {"type": "string", "pattern": "^[a-z]+$"}},
        }
        Draft4Validator(schema).validate({"name": "alice"})
        with pytest.raises(ValidationError):
            Draft4Validator(schema).validate({"name": "Alice123"})

    def test_cross_file_ref(self, tmp_path: Path) -> None:
        """Test cross-file reference resolution."""
        defs = {"definitions": {"my_type": {"type": "string"}}}
        main = {
            "type": "object",
            "properties": {"val": {"$ref": "defs.json#/definitions/my_type"}},
        }

        (tmp_path / "defs.json").write_text(json.dumps(defs))

        base_uri = tmp_path.absolute().as_uri() + "/"
        resolver = RefResolver(base_uri, main)
        Draft4Validator(main, resolver=resolver).validate({"val": "ok"})
        with pytest.raises(ValidationError):
            Draft4Validator(main, resolver=resolver).validate({"val": 123})

    def test_external_ref_without_resolver(self) -> None:
        """Test that external $ref without resolver raises ValidationError."""
        schema = {
            "type": "object",
            "properties": {"val": {"$ref": "other.json#/definitions/foo"}},
        }
        with pytest.raises(ValidationError, match="no RefResolver configured"):
            Draft4Validator(schema).validate({"val": "anything"})


# --- iter_errors ---


class TestIterErrors:
    """Tests for iter_errors method."""

    def test_multiple_errors(self) -> None:
        """Test that iter_errors yields all errors."""
        schema = {
            "type": "object",
            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
            "required": ["a", "b"],
        }
        errors = list(Draft4Validator(schema).iter_errors({"a": 1, "b": "x"}))
        assert len(errors) >= 2

    def test_error_has_path(self) -> None:
        """Test that errors have correct path."""
        schema = {
            "type": "object",
            "properties": {
                "nested": {"type": "object", "properties": {"x": {"type": "integer"}}}
            },
        }
        errors = list(Draft4Validator(schema).iter_errors({"nested": {"x": "bad"}}))
        assert len(errors) == 1
        assert list(errors[0].path) == ["nested", "x"]


# --- extend ---


class TestExtend:
    """Tests for extend() to create custom validators."""

    def test_custom_additional_properties(self) -> None:
        """Test extending with a custom additionalProperties handler."""
        custom_errors: List[str] = []

        def custom_ap(validator, aP, instance, schema):
            extras = list(find_additional_properties(instance, schema))
            if extras:
                custom_errors.extend(extras)
                yield ValidationError(f"custom: {extras}")

        MyValidator = extend(
            validator=Draft4Validator,
            validators={"additionalProperties": custom_ap},
        )
        schema = {
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "additionalProperties": False,
        }
        errors = list(MyValidator(schema).iter_errors({"a": "ok", "b": 1, "c": 2}))
        assert len(errors) == 1
        assert "b" in custom_errors
        assert "c" in custom_errors

    def test_custom_type_checker(self) -> None:
        """Test extending with a custom type checker for env vars."""

        class EnvVarTypeChecker:
            def __init__(self, base_checkers):
                self._base = base_checkers

            def is_type(self, instance, type_name):
                if isinstance(instance, str) and instance.startswith("$"):
                    return True
                return self._base.is_type(instance, type_name)

        base = Draft4Validator({})
        EnvFriendlyValidator = extend(
            validator=Draft4Validator,
            type_checker=EnvVarTypeChecker(base.TYPE_CHECKER),
        )
        schema = {"type": "object", "properties": {"port": {"type": "integer"}}}
        # Normal integer works
        EnvFriendlyValidator(schema).validate({"port": 8080})
        # Env var also works
        EnvFriendlyValidator(schema).validate({"port": "$MY_PORT"})
        # Non-env string still fails
        with pytest.raises(ValidationError):
            EnvFriendlyValidator(schema).validate({"port": "not_env"})


# --- Real schema integration ---


class TestRealSchemas:
    """Test against actual AEA configuration schemas."""

    def test_validate_skill_config(self) -> None:
        """Test validation against skill-config_schema.json."""
        schemas_dir = (
            Path(__file__).parent.parent.parent / "aea" / "configurations" / "schemas"
        )
        with open(schemas_dir / "skill-config_schema.json") as f:
            schema = json.load(f)

        base_uri = schemas_dir.absolute().as_uri() + "/"
        resolver = RefResolver(base_uri, schema)
        v = Draft4Validator(schema, resolver=resolver)

        valid = {
            "name": "my_skill",
            "author": "test_author",
            "version": "0.1.0",
            "type": "skill",
            "license": "Apache-2.0",
            "aea_version": ">=1.0.0, <2.0.0",
            "fingerprint": {},
            "fingerprint_ignore_patterns": [],
            "connections": [],
            "protocols": [],
            "contracts": [],
            "skills": [],
            "handlers": {},
            "behaviours": {},
            "models": {},
            "dependencies": {},
            "description": "A test skill",
            "is_abstract": False,
        }
        v.validate(valid)

        # Missing required field
        invalid = dict(valid)
        del invalid["name"]
        errors = list(v.iter_errors(invalid))
        assert any("required" in e.message or "name" in e.message for e in errors)

        # Extra field
        invalid2 = dict(valid, unknown_field="bad")
        errors2 = list(v.iter_errors(invalid2))
        assert len(errors2) > 0
