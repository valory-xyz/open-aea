<a id="aea.helpers.json_schema"></a>

# aea.helpers.json`_`schema

Inlined JSON Schema Draft-04 validator.

Replaces the external ``jsonschema`` package. Implements only the subset
of Draft-04 keywords used by the AEA configuration schemas.

Supported keywords: type, properties, patternProperties, required,
additionalProperties, items, enum, pattern, minimum, oneOf, uniqueItems,
$ref, definitions, default, description.

<a id="aea.helpers.json_schema.ValidationError"></a>

## ValidationError Objects

```python
class ValidationError(Exception)
```

JSON Schema validation error with path tracking.

<a id="aea.helpers.json_schema.ValidationError.__init__"></a>

#### `__`init`__`

```python
def __init__(message: str, path: Optional[Sequence] = None) -> None
```

Initialize ValidationError.

**Arguments**:

- `message`: error description.
- `path`: path to the failing element in the instance.

<a id="aea.helpers.json_schema.RefResolver"></a>

## RefResolver Objects

```python
class RefResolver()
```

Resolve JSON ``$ref`` pointers against a base URI and local schema store.

<a id="aea.helpers.json_schema.RefResolver.__init__"></a>

#### `__`init`__`

```python
def __init__(base_uri: str, referrer: Dict) -> None
```

Initialize resolver.

**Arguments**:

- `base_uri`: the base URI (file:// or http://) for cross-file refs.
- `referrer`: the root schema document.

<a id="aea.helpers.json_schema.RefResolver.resolve"></a>

#### resolve

```python
def resolve(ref: str, current_schema: Optional[Dict] = None) -> Dict
```

Resolve a ``$ref`` string to the target sub-schema.

**Arguments**:

- `ref`: the ``$ref`` value, e.g. ``#/definitions/foo`` or
``other.json#/definitions/bar``.
- `current_schema`: the schema containing this ``$ref`` (defaults to
the root referrer document).

**Returns**:

the resolved sub-schema dict.

<a id="aea.helpers.json_schema.TypeChecker"></a>

## TypeChecker Objects

```python
class TypeChecker()
```

Default type checker using the Draft-04 type map.

<a id="aea.helpers.json_schema.TypeChecker.is_type"></a>

#### is`_`type

```python
def is_type(instance: Any, type_name: str) -> bool
```

Check if instance matches the given type name.

**Arguments**:

- `instance`: the value to check.
- `type_name`: a JSON Schema type name.

**Returns**:

True if the instance matches.

<a id="aea.helpers.json_schema.find_additional_properties"></a>

#### find`_`additional`_`properties

```python
def find_additional_properties(instance: Dict, schema: Dict) -> Iterator[str]
```

Yield property names in *instance* not covered by the schema.

**Arguments**:

- `instance`: the object instance.
- `schema`: the schema with ``properties`` and/or ``patternProperties``.

**Returns**:

property names not covered by the schema.

<a id="aea.helpers.json_schema.Draft4Validator"></a>

## Draft4Validator Objects

```python
class Draft4Validator()
```

JSON Schema Draft-04 validator.

Supports: type, properties, patternProperties, required,
additionalProperties, items, enum, pattern, minimum, oneOf,
uniqueItems, $ref, definitions.

<a id="aea.helpers.json_schema.Draft4Validator.check_schema"></a>

#### check`_`schema

```python
@classmethod
def check_schema(cls, schema: Dict) -> None
```

Validate that a schema is a well-formed JSON Schema document.

**Arguments**:

- `schema`: the schema dict.

**Raises**:

- `ValueError`: if the schema is not a dict.

<a id="aea.helpers.json_schema.Draft4Validator.__init__"></a>

#### `__`init`__`

```python
def __init__(schema: Dict, resolver: Optional[RefResolver] = None) -> None
```

Initialize validator.

**Arguments**:

- `schema`: the JSON schema dict.
- `resolver`: optional RefResolver for cross-file ``$ref``.

<a id="aea.helpers.json_schema.Draft4Validator.validate"></a>

#### validate

```python
def validate(instance: Any) -> None
```

Validate an instance and raise on the first error.

**Arguments**:

- `instance`: the data to validate.

<a id="aea.helpers.json_schema.Draft4Validator.iter_errors"></a>

#### iter`_`errors

```python
def iter_errors(instance: Any) -> Iterator[ValidationError]
```

Yield all validation errors for the given instance.

**Arguments**:

- `instance`: the data to validate.

**Returns**:

validation errors.

<a id="aea.helpers.json_schema.extend"></a>

#### extend

```python
def extend(validator: Type[Draft4Validator],
           validators: Optional[Dict[str, ValidatorFn]] = None,
           type_checker: Optional[Any] = None) -> Type[Draft4Validator]
```

Create a new validator class by extending an existing one.

**Arguments**:

- `validator`: the base validator class.
- `validators`: dict of keyword -> validator function overrides.
- `type_checker`: optional custom type checker.

**Returns**:

a new validator class.

