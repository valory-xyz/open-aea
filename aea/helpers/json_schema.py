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

# pylint: disable=protected-access,unused-argument

"""
Inlined JSON Schema Draft-04 validator.

Replaces the external ``jsonschema`` package. Implements only the subset
of Draft-04 keywords used by the AEA configuration schemas.

Supported keywords: type, properties, patternProperties, required,
additionalProperties, items, enum, pattern, minimum, oneOf, uniqueItems,
$ref, definitions, default, description.
"""

import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Type
from urllib.parse import urljoin, urlsplit
from urllib.request import urlopen

# ---------------------------------------------------------------------------
# ValidationError
# ---------------------------------------------------------------------------


class ValidationError(Exception):
    """JSON Schema validation error with path tracking."""

    def __init__(self, message: str, path: Optional[Sequence] = None) -> None:
        """
        Initialize ValidationError.

        :param message: error description.
        :param path: path to the failing element in the instance.
        """
        super().__init__(message)
        self.message = message
        self.path: List = list(path) if path else []

    def _prepend_path(self, key: Any) -> "ValidationError":
        """Prepend a key to the error path (returns self)."""
        self.path.insert(0, key)
        return self


# ---------------------------------------------------------------------------
# RefResolver
# ---------------------------------------------------------------------------


class RefResolver:
    """Resolve JSON ``$ref`` pointers against a base URI and local schema store."""

    def __init__(self, base_uri: str, referrer: Dict) -> None:
        """
        Initialize resolver.

        :param base_uri: the base URI (file:// or http://) for cross-file refs.
        :param referrer: the root schema document.
        """
        self._base_uri = base_uri
        self._store: Dict[str, Dict] = {}
        self._store[base_uri] = referrer

    def resolve(self, ref: str, current_schema: Dict) -> Dict:
        """
        Resolve a ``$ref`` string to the target sub-schema.

        :param ref: the ``$ref`` value, e.g. ``#/definitions/foo`` or
            ``other.json#/definitions/bar``.
        :param current_schema: the schema containing this ``$ref``.
        :return: the resolved sub-schema dict.
        """
        if ref.startswith("#"):
            return self._resolve_pointer(ref[1:], current_schema)

        # Cross-file ref: "file.json#/definitions/foo"
        parts = ref.split("#", 1)
        file_ref = parts[0]
        pointer = parts[1] if len(parts) > 1 else ""

        full_uri = urljoin(self._base_uri, file_ref)
        if full_uri not in self._store:
            self._store[full_uri] = self._fetch(full_uri)

        target_schema = self._store[full_uri]
        if pointer:
            return self._resolve_pointer(pointer, target_schema)
        return target_schema

    @staticmethod
    def _resolve_pointer(pointer: str, document: Dict) -> Dict:
        """Resolve a JSON pointer like ``/definitions/foo``."""
        parts = [p for p in pointer.split("/") if p]
        node = document
        for part in parts:
            try:
                node = node[part]
            except (KeyError, TypeError) as e:
                raise ValueError(
                    f"Failed to resolve JSON pointer '{pointer}' at segment '{part}'"
                ) from e
        return node

    @staticmethod
    def _fetch(uri: str) -> Dict:
        """Fetch and parse a JSON document from a URI."""
        parsed = urlsplit(uri)
        if parsed.scheme == "file":
            path = Path(parsed.path)
            return json.loads(path.read_text(encoding="utf-8"))
        with urlopen(uri) as resp:  # pragma: nocover  # nosec B310
            return json.loads(resp.read().decode("utf-8"))


# ---------------------------------------------------------------------------
# Type checker
# ---------------------------------------------------------------------------

_TYPE_MAP = {
    "string": lambda x: isinstance(x, str),
    "integer": lambda x: isinstance(x, int) and not isinstance(x, bool),
    "number": lambda x: isinstance(x, (int, float)) and not isinstance(x, bool),
    "boolean": lambda x: isinstance(x, bool),
    "null": lambda x: x is None,
    "array": lambda x: isinstance(x, list),
    "object": lambda x: isinstance(x, dict),
}


class TypeChecker:
    """Default type checker using the Draft-04 type map."""

    def is_type(self, instance: Any, type_name: str) -> bool:
        """
        Check if instance matches the given type name.

        :param instance: the value to check.
        :param type_name: a JSON Schema type name.
        :return: True if the instance matches.
        """
        checker = _TYPE_MAP.get(type_name)
        if checker is None:
            return False
        return checker(instance)


_DEFAULT_TYPE_CHECKER = TypeChecker()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def find_additional_properties(instance: Dict, schema: Dict) -> Iterator[str]:
    """
    Yield property names in *instance* not covered by the schema.

    :param instance: the object instance.
    :param schema: the schema with ``properties`` and/or ``patternProperties``.
    :yield: property names not covered by the schema.
    """
    properties = schema.get("properties", {})
    patterns = "|".join(schema.get("patternProperties", {}))
    for prop in instance:
        if prop in properties:
            continue
        if patterns and re.search(patterns, prop):
            continue
        yield prop


# ---------------------------------------------------------------------------
# Core validation engine
# ---------------------------------------------------------------------------

# Validator keyword signature: (validator, keyword_value, instance, schema) -> Iterator[ValidationError]
ValidatorFn = Callable[..., Iterator[ValidationError]]


def _validate_type(
    validator: "Draft4Validator",
    type_value: Any,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``type`` keyword."""
    if isinstance(type_value, list):
        if not any(validator.TYPE_CHECKER.is_type(instance, t) for t in type_value):
            yield ValidationError(
                f"data must be one of types {type_value}, got {type(instance).__name__}"
            )
    elif isinstance(type_value, str):
        if not validator.TYPE_CHECKER.is_type(instance, type_value):
            yield ValidationError(
                f"data must be {type_value}, got {type(instance).__name__}"
            )


def _validate_properties(
    validator: "Draft4Validator",
    properties: Dict,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``properties`` keyword."""
    if not isinstance(instance, dict):
        return
    for prop, sub_schema in properties.items():
        if prop in instance:
            for err in validator._validate_schema(instance[prop], sub_schema):
                yield err._prepend_path(prop)


def _validate_pattern_properties(
    validator: "Draft4Validator",
    pattern_props: Dict,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``patternProperties`` keyword."""
    if not isinstance(instance, dict):
        return
    for pattern, sub_schema in pattern_props.items():
        for prop, value in instance.items():
            if re.search(pattern, prop):
                for err in validator._validate_schema(value, sub_schema):
                    yield err._prepend_path(prop)


def _validate_required(
    validator: "Draft4Validator",
    required: List[str],
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``required`` keyword."""
    if not isinstance(instance, dict):
        return
    for field in required:
        if field not in instance:
            yield ValidationError(
                f"data must contain ['{field}'] properties (required)"
            )


def _validate_additional_properties(
    validator: "Draft4Validator", aP: Any, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``additionalProperties`` keyword."""
    if not isinstance(instance, dict):
        return
    if aP is False:
        extras = list(find_additional_properties(instance, schema))
        if extras:
            yield ValidationError(
                f"data must not contain {set(extras)} properties (additionalProperties)"
            )
    elif isinstance(aP, dict):
        for prop in find_additional_properties(instance, schema):
            for err in validator._validate_schema(instance[prop], aP):
                yield err._prepend_path(prop)


def _validate_items(
    validator: "Draft4Validator",
    items: Dict,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``items`` keyword."""
    if not isinstance(instance, list):
        return
    for idx, item in enumerate(instance):
        for err in validator._validate_schema(item, items):
            yield err._prepend_path(idx)


def _validate_enum(
    validator: "Draft4Validator", enum: List, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``enum`` keyword."""
    if instance not in enum:
        yield ValidationError(f"data must be one of {enum} (enum)")


def _validate_pattern(
    validator: "Draft4Validator", pattern: str, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``pattern`` keyword."""
    if isinstance(instance, str) and not re.search(pattern, instance):
        yield ValidationError(f"data must match pattern {pattern!r} (pattern)")


def _validate_minimum(
    validator: "Draft4Validator", minimum: Any, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``minimum`` keyword."""
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        exclusive = schema.get("exclusiveMinimum", False)
        if exclusive and instance <= minimum:
            yield ValidationError(f"data must be > {minimum} (exclusiveMinimum)")
        elif not exclusive and instance < minimum:
            yield ValidationError(f"data must be >= {minimum} (minimum)")


def _validate_one_of(
    validator: "Draft4Validator", one_of: List[Dict], instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``oneOf`` keyword."""
    matches = 0
    for sub_schema in one_of:
        errors = list(validator._validate_schema(instance, sub_schema))
        if not errors:
            matches += 1
    if matches != 1:
        yield ValidationError(
            f"data must match exactly one of the given schemas (oneOf), matched {matches}"
        )


def _validate_property_names(
    validator: "Draft4Validator",
    property_names: Dict,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``propertyNames`` keyword."""
    if not isinstance(instance, dict):
        return
    for prop in instance:
        for err in validator._validate_schema(prop, property_names):
            yield err._prepend_path(prop)


def _validate_unique_items(
    validator: "Draft4Validator", unique: bool, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``uniqueItems`` keyword."""
    if not unique or not isinstance(instance, list):
        return
    seen: list = []
    for item in instance:
        if item in seen:
            yield ValidationError("data items must be unique (uniqueItems)")
            return
        seen.append(item)


# Default keyword validators
_KEYWORD_VALIDATORS: Dict[str, ValidatorFn] = {
    "type": _validate_type,
    "properties": _validate_properties,
    "patternProperties": _validate_pattern_properties,
    "required": _validate_required,
    "additionalProperties": _validate_additional_properties,
    "items": _validate_items,
    "enum": _validate_enum,
    "pattern": _validate_pattern,
    "minimum": _validate_minimum,
    "oneOf": _validate_one_of,
    "uniqueItems": _validate_unique_items,
    "propertyNames": _validate_property_names,
}


# ---------------------------------------------------------------------------
# Draft4Validator
# ---------------------------------------------------------------------------


class Draft4Validator:
    """
    JSON Schema Draft-04 validator.

    Supports: type, properties, patternProperties, required,
    additionalProperties, items, enum, pattern, minimum, oneOf,
    uniqueItems, $ref, definitions.
    """

    TYPE_CHECKER: TypeChecker = _DEFAULT_TYPE_CHECKER
    VALIDATORS: Dict[str, ValidatorFn] = _KEYWORD_VALIDATORS

    @classmethod
    def check_schema(cls, schema: Dict) -> None:
        """
        Validate that a schema is a well-formed JSON Schema document.

        :param schema: the schema dict.
        :raises ValueError: if the schema is not a dict.
        """
        if not isinstance(schema, dict):
            raise ValueError(f"Schema must be a dict, got {type(schema).__name__}")

    def __init__(
        self,
        schema: Dict,
        resolver: Optional[RefResolver] = None,
    ) -> None:
        """
        Initialize validator.

        :param schema: the JSON schema dict.
        :param resolver: optional RefResolver for cross-file ``$ref``.
        """
        self.schema = schema
        self.resolver = resolver
        self._current_root: Optional[Dict] = None

    def validate(self, instance: Any) -> None:
        """
        Validate an instance and raise on the first error.

        :param instance: the data to validate.
        """
        first_error = next(self.iter_errors(instance), None)
        if first_error is not None:
            raise first_error

    def iter_errors(self, instance: Any) -> Iterator[ValidationError]:
        """
        Yield all validation errors for the given instance.

        :param instance: the data to validate.
        :yield: validation errors.
        """
        self._current_root = self.schema
        yield from self._validate_schema(instance, self.schema)

    def _validate_schema(
        self, instance: Any, schema: Dict
    ) -> Iterator[ValidationError]:
        """Validate an instance against a (sub-)schema."""
        # Resolve $ref
        if "$ref" in schema:
            ref = schema["$ref"]
            if ref.startswith("#"):
                if self._current_root is None:  # pragma: nocover
                    raise ValueError("No root schema set")
                resolved = RefResolver._resolve_pointer(ref[1:], self._current_root)
                yield from self._validate_schema(instance, resolved)
            elif self.resolver is None:
                yield ValidationError(
                    f"Cannot resolve external $ref '{ref}': no RefResolver configured"
                )
            else:
                if self._current_root is None:  # pragma: nocover
                    raise ValueError("No root schema set")
                resolved = self.resolver.resolve(ref, self._current_root)
                # Switch root context to the external document for nested refs
                file_part = ref.split("#", 1)[0]
                prev_root = self._current_root
                if file_part:
                    full_uri = urljoin(self.resolver._base_uri, file_part)
                    self._current_root = self.resolver._store.get(full_uri, prev_root)
                yield from self._validate_schema(instance, resolved)
                self._current_root = prev_root
            return

        # Apply each keyword validator
        for keyword, validator_fn in self.__class__.VALIDATORS.items():
            if keyword in schema:
                yield from validator_fn(self, schema[keyword], instance, schema)


# ---------------------------------------------------------------------------
# Validator extension helper
# ---------------------------------------------------------------------------


def extend(
    validator: Type[Draft4Validator],
    validators: Optional[Dict[str, ValidatorFn]] = None,
    type_checker: Optional[Any] = None,
) -> Type[Draft4Validator]:
    """
    Create a new validator class by extending an existing one.

    :param validator: the base validator class.
    :param validators: dict of keyword -> validator function overrides.
    :param type_checker: optional custom type checker.
    :return: a new validator class.
    """
    merged_validators = dict(validator.VALIDATORS)
    if validators:
        merged_validators.update(validators)

    tc = type_checker if type_checker is not None else validator.TYPE_CHECKER

    new_cls = type(
        f"{validator.__name__}Extended",
        (validator,),
        {"VALIDATORS": merged_validators, "TYPE_CHECKER": tc},
    )
    return new_cls
