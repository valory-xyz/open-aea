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

Supported keywords: type, properties, patternProperties, propertyNames,
required, additionalProperties, items, enum, pattern, minimum, maximum,
exclusiveMinimum, exclusiveMaximum, minLength, maxLength, minItems,
maxItems, oneOf, anyOf, allOf, not, uniqueItems, dependencies,
additionalItems, $ref, definitions, default, description.
"""

import contextvars
import json
import re
from pathlib import Path
from typing import Any, Callable, Dict, Iterator, List, Optional, Sequence, Type
from urllib.parse import urljoin, urlsplit
from urllib.request import url2pathname, urlopen

# Thread-safe / async-safe context for $ref root tracking
_current_root_var: contextvars.ContextVar[Optional[Dict]] = contextvars.ContextVar(
    "_current_root", default=None
)

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

    def resolve(self, ref: str, current_schema: Optional[Dict] = None) -> Dict:
        """
        Resolve a ``$ref`` string to the target sub-schema.

        :param ref: the ``$ref`` value, e.g. ``#/definitions/foo`` or
            ``other.json#/definitions/bar``.
        :param current_schema: the schema containing this ``$ref`` (defaults to
            the root referrer document).
        :return: the resolved sub-schema dict.
        """
        if current_schema is None:
            current_schema = self._store.get(self._base_uri, {})
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
        """Resolve a JSON pointer (RFC 6901) like ``/definitions/foo``."""
        if not pointer:
            return document
        parts = pointer.split("/")
        # Leading '/' produces an empty first element — skip it
        if parts and parts[0] == "":
            parts = parts[1:]
        node = document
        for part in parts:
            # RFC 6901 unescaping: ~1 -> /, ~0 -> ~
            part = part.replace("~1", "/").replace("~0", "~")
            try:
                if isinstance(node, list):
                    # RFC 6901: indices must be non-negative, no leading zeros
                    if part != "0" and (part.startswith("0") or part.startswith("-")):
                        raise ValueError(f"Invalid array index: {part!r}")
                    node = node[int(part)]
                else:
                    node = node[part]
            except (KeyError, TypeError, ValueError, IndexError) as e:
                raise ValueError(
                    f"Failed to resolve JSON pointer '{pointer}' at segment '{part}'"
                ) from e
        return node

    @staticmethod
    def _fetch(uri: str) -> Dict:
        """Fetch and parse a JSON document from a URI."""
        parsed = urlsplit(uri)
        if parsed.scheme == "file":
            # url2pathname handles Windows drive letters correctly
            path = Path(url2pathname(parsed.path))
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
    pattern_list = list(schema.get("patternProperties", {}).keys())
    for prop in instance:
        if prop in properties:
            continue
        prop_str = str(prop) if not isinstance(prop, str) else prop
        matched = False
        for p in pattern_list:
            try:
                if re.search(p, prop_str):
                    matched = True
                    break
            except re.error:
                continue  # skip invalid pattern, check others
        if not matched:
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
            types = ", ".join(repr(t) for t in type_value)
            yield ValidationError(f"{instance!r} is not of type {types}")
    elif isinstance(type_value, str):
        if not validator.TYPE_CHECKER.is_type(instance, type_value):
            yield ValidationError(f"{instance!r} is not of type {type_value!r}")


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
            prop_str = str(prop) if not isinstance(prop, str) else prop
            try:
                matched = re.search(pattern, prop_str)
            except re.error:
                continue
            if matched:
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
            yield ValidationError(f"{field!r} is a required property")


def _validate_additional_properties(
    validator: "Draft4Validator", aP: Any, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``additionalProperties`` keyword."""
    if not isinstance(instance, dict):
        return
    if aP is False:
        extras = list(find_additional_properties(instance, schema))
        for extra in extras:
            yield ValidationError(
                f"Additional properties are not allowed ({extra!r} was unexpected)"
            )
    elif isinstance(aP, dict):
        for prop in find_additional_properties(instance, schema):
            for err in validator._validate_schema(instance[prop], aP):
                yield err._prepend_path(prop)


def _validate_items(
    validator: "Draft4Validator",
    items: Any,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``items`` keyword."""
    if not isinstance(instance, list):
        return
    if isinstance(items, list):
        # Tuple validation: each item validated against positional schema
        for idx, (item, item_schema) in enumerate(zip(instance, items)):
            for err in validator._validate_schema(item, item_schema):
                yield err._prepend_path(idx)
    elif isinstance(items, dict):
        # All items validated against single schema
        for idx, item in enumerate(instance):
            for err in validator._validate_schema(item, items):
                yield err._prepend_path(idx)


def _strict_equal(a: Any, b: Any) -> bool:
    """Deep type-aware equality: booleans and integers are distinguished.

    :param a: first value.
    :param b: second value.
    :return: True if a and b are deeply equal with type awareness.
    """
    # Distinguish bool from int (JSON Schema treats them as different types)
    if isinstance(a, bool) != isinstance(b, bool):
        return False
    # Recursively compare dicts (including OrderedDict and other Mappings)
    if isinstance(a, dict) and isinstance(b, dict):
        if set(a.keys()) != set(b.keys()):
            return False
        return all(_strict_equal(a[k], b[k]) for k in a)
    # Recursively compare lists (including tuples)
    if isinstance(a, (list, tuple)) and isinstance(b, (list, tuple)):
        if len(a) != len(b):
            return False
        return all(_strict_equal(x, y) for x, y in zip(a, b))
    # For scalars, use standard equality
    return a == b


def _strict_enum_contains(enum: List, instance: Any) -> bool:  # noqa: DAR
    """Check if instance is in enum with deep type-aware equality.

    Booleans and integers are distinguished at all nesting levels.

    :param enum: the allowed values.
    :param instance: the value to check.
    :return: True if instance matches any enum value with type awareness.
    """
    for val in enum:
        if _strict_equal(val, instance):
            return True
    return False


def _validate_enum(
    validator: "Draft4Validator", enum: List, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``enum`` keyword."""
    if not _strict_enum_contains(enum, instance):
        yield ValidationError(f"{instance!r} is not one of {enum!r}")


def _validate_pattern(
    validator: "Draft4Validator", pattern: str, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``pattern`` keyword."""
    if not isinstance(instance, str):
        return
    try:
        if not re.search(pattern, instance):
            yield ValidationError(f"{instance!r} does not match {pattern!r}")
    except re.error as e:
        yield ValidationError(f"Invalid regex pattern {pattern!r}: {e}")


def _validate_minimum(
    validator: "Draft4Validator", minimum: Any, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``minimum`` keyword."""
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        exclusive = schema.get("exclusiveMinimum", False)
        if exclusive and instance <= minimum:
            yield ValidationError(
                f"{instance} is less than or equal to the minimum of {minimum}"
            )
        elif not exclusive and instance < minimum:
            yield ValidationError(f"{instance} is less than the minimum of {minimum}")


def _validate_one_of(
    validator: "Draft4Validator", one_of: List[Dict], instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``oneOf`` keyword."""
    matches = 0
    for sub_schema in one_of:
        first_error = next(validator._validate_schema(instance, sub_schema), None)
        if first_error is None:
            matches += 1
    if matches == 0:
        yield ValidationError(
            f"{instance!r} is not valid under any of the given schemas"
        )
    elif matches > 1:
        yield ValidationError(f"{instance!r} is valid under each of {matches} schemas")


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
        if any(_strict_equal(item, s) for s in seen):
            yield ValidationError(f"{instance!r} has non-unique elements")
            return
        seen.append(item)


def _validate_maximum(
    validator: "Draft4Validator", maximum: Any, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``maximum`` keyword."""
    if isinstance(instance, (int, float)) and not isinstance(instance, bool):
        exclusive = schema.get("exclusiveMaximum", False)
        if exclusive and instance >= maximum:
            yield ValidationError(
                f"{instance} is greater than or equal to the maximum of {maximum}"
            )
        elif not exclusive and instance > maximum:
            yield ValidationError(
                f"{instance} is greater than the maximum of {maximum}"
            )


def _validate_min_length(
    validator: "Draft4Validator", min_length: int, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``minLength`` keyword."""
    if isinstance(instance, str) and len(instance) < min_length:
        yield ValidationError(f"{instance!r} is too short")


def _validate_max_length(
    validator: "Draft4Validator", max_length: int, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``maxLength`` keyword."""
    if isinstance(instance, str) and len(instance) > max_length:
        yield ValidationError(f"{instance!r} is too long")


def _validate_min_items(
    validator: "Draft4Validator", min_items: int, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``minItems`` keyword."""
    if isinstance(instance, list) and len(instance) < min_items:
        yield ValidationError(f"{instance!r} is too short")


def _validate_max_items(
    validator: "Draft4Validator", max_items: int, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``maxItems`` keyword."""
    if isinstance(instance, list) and len(instance) > max_items:
        yield ValidationError(f"{instance!r} is too long")


def _validate_any_of(
    validator: "Draft4Validator", any_of: List[Dict], instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``anyOf`` keyword."""
    for sub_schema in any_of:
        if next(validator._validate_schema(instance, sub_schema), None) is None:
            return
    yield ValidationError(f"{instance!r} is not valid under any of the given schemas")


def _validate_all_of(
    validator: "Draft4Validator", all_of: List[Dict], instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``allOf`` keyword."""
    for sub_schema in all_of:
        yield from validator._validate_schema(instance, sub_schema)


def _validate_not(
    validator: "Draft4Validator", not_schema: Dict, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``not`` keyword."""
    if next(validator._validate_schema(instance, not_schema), None) is None:
        yield ValidationError(
            f"{instance!r} should not be valid under the given schema"
        )


def _validate_dependencies(
    validator: "Draft4Validator", dependencies: Dict, instance: Any, schema: Dict
) -> Iterator[ValidationError]:
    """Validate the ``dependencies`` keyword."""
    if not isinstance(instance, dict):
        return
    for prop, dep in dependencies.items():
        if prop not in instance:
            continue
        if isinstance(dep, list):
            for required_prop in dep:
                if required_prop not in instance:
                    yield ValidationError(
                        f"{required_prop!r} is a dependency of {prop!r}"
                    )
        elif isinstance(dep, dict):
            yield from validator._validate_schema(instance, dep)


def _validate_additional_items(
    validator: "Draft4Validator",
    additional_items: Any,
    instance: Any,
    schema: Dict,
) -> Iterator[ValidationError]:
    """Validate the ``additionalItems`` keyword."""
    if not isinstance(instance, list):
        return
    items = schema.get("items")
    if not isinstance(items, list):
        return
    if additional_items is False and len(instance) > len(items):
        yield ValidationError("Additional items are not allowed")
    elif isinstance(additional_items, dict):
        for idx in range(len(items), len(instance)):
            for err in validator._validate_schema(instance[idx], additional_items):
                yield err._prepend_path(idx)


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
    "anyOf": _validate_any_of,
    "allOf": _validate_all_of,
    "not": _validate_not,
    "uniqueItems": _validate_unique_items,
    "propertyNames": _validate_property_names,
    "maximum": _validate_maximum,
    "minLength": _validate_min_length,
    "maxLength": _validate_max_length,
    "minItems": _validate_min_items,
    "maxItems": _validate_max_items,
    "dependencies": _validate_dependencies,
    "additionalItems": _validate_additional_items,
}


# ---------------------------------------------------------------------------
# Draft4Validator
# ---------------------------------------------------------------------------


class Draft4Validator:
    """
    JSON Schema Draft-04 validator.

    Supports all Draft-04 keywords: type, properties, patternProperties,
    propertyNames, required, additionalProperties, items, additionalItems,
    enum, pattern, minimum, maximum, exclusiveMinimum, exclusiveMaximum,
    minLength, maxLength, minItems, maxItems, oneOf, anyOf, allOf, not,
    uniqueItems, dependencies, $ref, definitions.
    """

    TYPE_CHECKER: TypeChecker = _DEFAULT_TYPE_CHECKER
    VALIDATORS: Dict[str, ValidatorFn] = _KEYWORD_VALIDATORS

    # Draft-04 meta-schema for validating schemas themselves
    META_SCHEMA: Dict = json.loads(
        '{"id":"http://json-schema.org/draft-04/schema#","$schema":"http://json-schema.org/draft-04/schema#","description":"Core schema meta-schema","definitions":{"schemaArray":{"type":"array","minItems":1,"items":{"$ref":"#"}},"positiveInteger":{"type":"integer","minimum":0},"positiveIntegerDefault0":{"allOf":[{"$ref":"#/definitions/positiveInteger"},{"default":0}]},"simpleTypes":{"enum":["array","boolean","integer","null","number","object","string"]},"stringArray":{"type":"array","items":{"type":"string"},"minItems":1,"uniqueItems":true}},"type":"object","properties":{"id":{"type":"string"},"$schema":{"type":"string"},"title":{"type":"string"},"description":{"type":"string"},"default":{},"multipleOf":{"type":"number","minimum":0,"exclusiveMinimum":true},"maximum":{"type":"number"},"exclusiveMaximum":{"type":"boolean","default":false},"minimum":{"type":"number"},"exclusiveMinimum":{"type":"boolean","default":false},"maxLength":{"$ref":"#/definitions/positiveInteger"},"minLength":{"$ref":"#/definitions/positiveIntegerDefault0"},"pattern":{"type":"string"},"additionalItems":{"anyOf":[{"type":"boolean"},{"$ref":"#"}],"default":{}},"items":{"anyOf":[{"$ref":"#"},{"$ref":"#/definitions/schemaArray"}],"default":{}},"maxItems":{"$ref":"#/definitions/positiveInteger"},"minItems":{"$ref":"#/definitions/positiveIntegerDefault0"},"uniqueItems":{"type":"boolean","default":false},"maxProperties":{"$ref":"#/definitions/positiveInteger"},"minProperties":{"$ref":"#/definitions/positiveIntegerDefault0"},"required":{"$ref":"#/definitions/stringArray"},"additionalProperties":{"anyOf":[{"type":"boolean"},{"$ref":"#"}],"default":{}},"definitions":{"type":"object","additionalProperties":{"$ref":"#"},"default":{}},"properties":{"type":"object","additionalProperties":{"$ref":"#"},"default":{}},"patternProperties":{"type":"object","additionalProperties":{"$ref":"#"},"default":{}},"dependencies":{"type":"object","additionalProperties":{"anyOf":[{"$ref":"#"},{"$ref":"#/definitions/stringArray"}]}},"enum":{"type":"array","minItems":1,"uniqueItems":true},"type":{"anyOf":[{"$ref":"#/definitions/simpleTypes"},{"type":"array","items":{"$ref":"#/definitions/simpleTypes"},"minItems":1,"uniqueItems":true}]},"allOf":{"$ref":"#/definitions/schemaArray"},"anyOf":{"$ref":"#/definitions/schemaArray"},"oneOf":{"$ref":"#/definitions/schemaArray"},"not":{"$ref":"#"}},"dependencies":{"exclusiveMaximum":["maximum"],"exclusiveMinimum":["minimum"]},"default":{}}'
    )

    @classmethod
    def check_schema(cls, schema: Dict) -> None:
        """
        Validate that a schema is a well-formed JSON Schema document.

        Validates *schema* against the Draft-04 meta-schema.

        :param schema: the schema dict.
        """
        v = cls(cls.META_SCHEMA)
        v.validate(schema)

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
        token = _current_root_var.set(self.schema)
        try:
            yield from self._validate_schema(instance, self.schema)
        finally:
            _current_root_var.reset(token)

    def _validate_schema(
        self, instance: Any, schema: Dict
    ) -> Iterator[ValidationError]:
        """Validate an instance against a (sub-)schema."""
        # Resolve $ref
        if "$ref" in schema:
            ref = schema["$ref"]
            current_root = _current_root_var.get()
            try:
                if ref.startswith("#"):
                    if current_root is None:  # pragma: nocover
                        raise ValueError("No root schema set")
                    resolved = RefResolver._resolve_pointer(ref[1:], current_root)
                    yield from self._validate_schema(instance, resolved)
                elif self.resolver is None:
                    yield ValidationError(
                        f"Cannot resolve external $ref {ref!r}: "
                        f"no RefResolver configured"
                    )
                else:
                    if current_root is None:  # pragma: nocover
                        raise ValueError("No root schema set")
                    resolved = self.resolver.resolve(ref, current_root)
                    # Switch root context for nested refs
                    file_part = ref.split("#", 1)[0]
                    if file_part:
                        full_uri = urljoin(self.resolver._base_uri, file_part)
                        new_root = self.resolver._store.get(full_uri, current_root)
                        token = _current_root_var.set(new_root)
                        try:
                            yield from self._validate_schema(instance, resolved)
                        finally:
                            _current_root_var.reset(token)
                    else:
                        yield from self._validate_schema(instance, resolved)
            except ValueError as e:
                yield ValidationError(str(e))
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
