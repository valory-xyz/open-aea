<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject"></a>

# plugins.aea-ci-helpers.aea`_`ci`_`helpers.check`_`pyproject

This script checks that dependencies in tox.ini and pyproject.toml match.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.Requirement"></a>

## Requirement Objects

```python
class Requirement(BaseRequirement)
```

Requirement with comparison

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.Requirement.__eq__"></a>

#### `__`eq`__`

```python
def __eq__(__value: object) -> bool
```

Compare two objects.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.Requirement.__hash__"></a>

#### `__`hash`__`

```python
def __hash__() -> int
```

Get hash for object.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.load_pyproject"></a>

#### load`_`pyproject

```python
def load_pyproject(filename: str = PYPROJECT_TOML) -> Set[Requirement]
```

Load pyproject.toml dev dependencies.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.load_tox_ini"></a>

#### load`_`tox`_`ini

```python
def load_tox_ini(file_name: str = TOX_INI) -> Set[Requirement]
```

Load tox.ini requirements.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.get_missing_packages"></a>

#### get`_`missing`_`packages

```python
def get_missing_packages() -> Tuple[Set[Requirement], Set[Requirement]]
```

Get difference in tox.ini and pyproject.toml.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pyproject.check_versions_are_correct"></a>

#### check`_`versions`_`are`_`correct

```python
def check_versions_are_correct() -> bool
```

Check no missing packages.

