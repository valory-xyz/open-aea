<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.bump`_`version

Bump the AEA version throughout the code base.

This module contains the logic originally in ``scripts/bump_aea_version.py``.

Example usage from the CLI wrapper::

    bump_aea_version --new-version 1.1.0 \\
        -p open-aea-ledger-fetchai=2.0.0 \\
        -p open-aea-ledger-ethereum=3.0.0

    bump_aea_version --only-check

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.ALL_PLUGINS"></a>

#### ALL`_`PLUGINS

This pattern captures a specifier set in the dependencies section
of an AEA package configuration file, e.g.:

dependencies:
    ...
    open-aea-ledger-fetchai:
        version: >=2.0.0,<3.0.0

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.YAML_DEPENDENCY_SPECIFIER_SET_PATTERN"></a>

#### YAML`_`DEPENDENCY`_`SPECIFIER`_`SET`_`PATTERN

This pattern captures a specifier set for PyPI dependencies
in JSON format.

e.g.:
"open-aea-ledger-fetchai": {"version": ">=2.0.0, <3.0.0"}

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.check_executed"></a>

#### check`_`executed

```python
def check_executed(func: Callable) -> Callable
```

Check a functor has been already executed; if yes, raise error.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.compute_specifier_from_version_custom"></a>

#### compute`_`specifier`_`from`_`version`_`custom

```python
def compute_specifier_from_version_custom(version: Version) -> str
```

Post-process aea.helpers.compute_specifier_from_version

The output is post-process in the following way:
- remove spaces between specifier sets
- put upper bound before lower bound

**Arguments**:

- `version`: the version

**Returns**:

the specifier set according to the version and semantic versioning.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.get_regex_from_specifier_set"></a>

#### get`_`regex`_`from`_`specifier`_`set

```python
def get_regex_from_specifier_set(specifier_set: str) -> str
```

Get the regex for specifier sets.

This function accepts input of the form:

    ">={lower_bound_version}, <{upper_bound_version}"

And computes a regex pattern:

    ">={lower_bound_version}, *<{upper_bound_version}|<{upper_bound_version}, *>={lower_bound_version}"

i.e. not considering the order of the specifiers.

**Arguments**:

- `specifier_set`: The string representation of the specifier set

**Returns**:

a regex pattern

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper"></a>

## PythonPackageVersionBumper Objects

```python
class PythonPackageVersionBumper()
```

Utility class to bump Python package versions.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.__init__"></a>

#### `__`init`__`

```python
def __init__(root_dir: Path,
             python_pkg_dir: Path,
             new_version: Version,
             files_to_pattern: PatternByPath,
             specifier_set_patterns: Sequence[str],
             package_name: Optional[str] = None,
             ignore_dirs: Sequence[Path] = ())
```

Initialize the utility class.

**Arguments**:

- `root_dir`: the root directory from which to look for files.
- `python_pkg_dir`: the path to the Python package to upgrade.
- `new_version`: the new version.
- `files_to_pattern`: a list of pairs.
- `specifier_set_patterns`: a list of patterns for specifier sets.
- `package_name`: the Python package name aliases (defaults to dirname of python_pkg_dir).
- `ignore_dirs`: a list of paths to ignore during the substitution.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.is_executed"></a>

#### is`_`executed

```python
@property
def is_executed() -> bool
```

Return true if the functor has been executed; false otherwise.

**Returns**:

True if it has been executed, False otherwise.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.result"></a>

#### result

```python
@property
def result() -> bool
```

Get the result.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.run"></a>

#### run

```python
@check_executed
def run() -> bool
```

Main entrypoint.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.update_version_for_files"></a>

#### update`_`version`_`for`_`files

```python
def update_version_for_files() -> None
```

Update the version.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.update_version_for_package"></a>

#### update`_`version`_`for`_`package

```python
def update_version_for_package(new_version: str) -> str
```

Update version for file.

If __version__.py is available, parse it and check for __version__ variable.
Otherwise, try to parse setup.py.
Otherwise, raise error.

**Arguments**:

- `new_version`: the new version

**Returns**:

the current version

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.update_version_for_file"></a>

#### update`_`version`_`for`_`file

```python
def update_version_for_file(
        path: Path,
        current_version: str,
        new_version: str,
        version_regex_template: Optional[str] = None) -> None
```

Update version for file.

**Arguments**:

- `path`: the file path
- `current_version`: the regex for the current version
- `new_version`: the new version
- `version_regex_template`: the regex template to replace with the current version. Defaults to exactly the current version.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.update_version_specifiers"></a>

#### update`_`version`_`specifiers

```python
def update_version_specifiers(old_version: Version,
                              new_version: Version) -> bool
```

Update specifier set.

**Arguments**:

- `old_version`: the old version.
- `new_version`: the new version.

**Returns**:

True if the update has been done, False otherwise.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.PythonPackageVersionBumper.is_different_from_latest_tag"></a>

#### is`_`different`_`from`_`latest`_`tag

```python
def is_different_from_latest_tag() -> bool
```

Check whether the package has changes since the latest tag.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.make_aea_bumper"></a>

#### make`_`aea`_`bumper

```python
def make_aea_bumper(new_aea_version: Version) -> PythonPackageVersionBumper
```

Build the AEA Python package version bumper.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.make_plugin_bumper"></a>

#### make`_`plugin`_`bumper

```python
def make_plugin_bumper(plugin_dir: Path,
                       new_version: Version) -> PythonPackageVersionBumper
```

Build the plugin Python package version bumper.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.process_plugins"></a>

#### process`_`plugins

```python
def process_plugins(new_versions: Dict[str, Version]) -> bool
```

Process plugins.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.parse_plugin_versions"></a>

#### parse`_`plugin`_`versions

```python
def parse_plugin_versions(key_value_strings: List[str]) -> Dict[str, Version]
```

Parse plugin versions.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.only_check_bump_needed"></a>

#### only`_`check`_`bump`_`needed

```python
def only_check_bump_needed() -> int
```

Check whether a version bump is needed for AEA and plugins.

**Returns**:

the return code

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.bump"></a>

#### bump

```python
def bump(new_version: Optional[str], plugin_new_version: List[str],
         no_fingerprints: bool) -> int
```

Bump versions.

**Arguments**:

- `new_version`: the new AEA version string (or None to skip AEA bump).
- `plugin_new_version`: list of ``plugin-name=version`` strings.
- `no_fingerprints`: if True, skip fingerprint computation.

**Returns**:

the return code

<a id="plugins.aea-dev-helpers.aea_dev_helpers.bump_version.run_bump"></a>

#### run`_`bump

```python
def run_bump(new_version: Optional[str] = None,
             plugin_new_version: Optional[List[str]] = None,
             no_fingerprints: bool = False,
             only_check: bool = False) -> None
```

Run the bump-aea-version workflow.

This is the main entry point intended to be called from a CLI wrapper.

**Arguments**:

- `new_version`: the new AEA version string (or None).
- `plugin_new_version`: list of ``plugin-name=version`` strings.
- `no_fingerprints`: if True, skip fingerprint computation.
- `only_check`: if True, only check whether a bump is needed.

