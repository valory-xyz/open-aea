<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions"></a>

# plugins.aea-ci-helpers.aea`_`ci`_`helpers.check`_`pkg`_`versions

Check that package ids are in sync with the current packages.

Run this script from the root of the project directory:

    python scripts/check_package_versions_in_docs.py

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.PUBLIC_ID_REGEX"></a>

#### PUBLIC`_`ID`_`REGEX

This regex removes the '^' and '$' respectively, at the beginning and at the end.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.ADD_COMMAND_IN_DOCS"></a>

#### ADD`_`COMMAND`_`IN`_`DOCS

This regex matches strings of the form:

  aea add (protocol|connection|contract|skill) some_author/some_package:some_version_number

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.FETCH_COMMAND_IN_DOCS"></a>

#### FETCH`_`COMMAND`_`IN`_`DOCS

This regex matches strings of the form:

  aea fetch some_author/some_package:some_version_number

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.PackageIdNotFound"></a>

## PackageIdNotFound Objects

```python
class PackageIdNotFound(Exception)
```

Custom exception for package id not found.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.PackageIdNotFound.__init__"></a>

#### `__`init`__`

```python
def __init__(file: Path, package_id: PackageId, match_obj: Any, *args:
             Any) -> None
```

Initialize PackageIdNotFound exception.

**Arguments**:

- `file`: path to the file checked.
- `package_id`: package id not found.
- `match_obj`: re.Match object.
- `args`: super class args.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.default_config_file_paths"></a>

#### default`_`config`_`file`_`paths

```python
def default_config_file_paths() -> Generator
```

Get (generator) the default config file paths.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.unified_yaml_load"></a>

#### unified`_`yaml`_`load

```python
def unified_yaml_load(configuration_file: Path) -> Dict
```

Load YAML file, unified (both single- and multi-paged).

**Arguments**:

- `configuration_file`: the configuration file path.

**Returns**:

the data.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.get_public_id_from_yaml"></a>

#### get`_`public`_`id`_`from`_`yaml

```python
def get_public_id_from_yaml(configuration_file: Path) -> PublicId
```

Get the public id from yaml.

**Arguments**:

- `configuration_file`: the path to the config yaml

**Returns**:

public id

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.find_all_packages_ids"></a>

#### find`_`all`_`packages`_`ids

```python
def find_all_packages_ids() -> Set[PackageId]
```

Find all packages ids.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.check_add_commands"></a>

#### check`_`add`_`commands

```python
def check_add_commands(file: Path) -> None
```

Check that 'aea add' commands of the documentation file contains known package ids.

**Arguments**:

- `file`: path to the file.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.check_fetch_commands"></a>

#### check`_`fetch`_`commands

```python
def check_fetch_commands(file: Path) -> None
```

Check that 'aea fetch' commands of the documentation file contains known package ids.

**Arguments**:

- `file`: path to the file.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.check_file"></a>

#### check`_`file

```python
def check_file(file: Path) -> None
```

Check documentation file.

**Arguments**:

- `file`: path to the file to check.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.check_pkg_versions.handle_package_not_found"></a>

#### handle`_`package`_`not`_`found

```python
def handle_package_not_found(e: PackageIdNotFound) -> None
```

Handle PackageIdNotFound errors.

