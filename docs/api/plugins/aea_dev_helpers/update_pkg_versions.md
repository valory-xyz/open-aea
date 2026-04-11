<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.update`_`pkg`_`versions

Updates package versions relative to last release.

This module contains the logic originally in ``scripts/update_package_versions.py``.

Run from the root of the project directory::

    aea-dev update-pkg-versions

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_protocol_specification_header_regex"></a>

#### get`_`protocol`_`specification`_`header`_`regex

```python
def get_protocol_specification_header_regex(public_id) -> Pattern
```

Get the regex to match.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.check_positive"></a>

#### check`_`positive

```python
def check_positive(value: Any) -> int
```

Check value is an int.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.check_if_running_allowed"></a>

#### check`_`if`_`running`_`allowed

```python
def check_if_running_allowed() -> None
```

Check if we can run the script.

Script should only be run on a clean branch.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.run_hashing"></a>

#### run`_`hashing

```python
def run_hashing() -> None
```

Run the hashing script.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_hashes_from_last_release"></a>

#### get`_`hashes`_`from`_`last`_`release

```python
def get_hashes_from_last_release() -> Dict[str, str]
```

Get hashes from last release.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_hashes_from_current_release"></a>

#### get`_`hashes`_`from`_`current`_`release

```python
def get_hashes_from_current_release() -> Dict[str, str]
```

Get hashes from last release.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.split_hashes_by_type"></a>

#### split`_`hashes`_`by`_`type

```python
def split_hashes_by_type(
        all_hashes: Dict[str, str]) -> Dict[str, Dict[str, str]]
```

Split hashes by type.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_configuration_file_path"></a>

#### get`_`configuration`_`file`_`path

```python
def get_configuration_file_path(type_: str, name: str) -> Path
```

Get the configuration file path.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.unified_yaml_load"></a>

#### unified`_`yaml`_`load

```python
def unified_yaml_load(configuration_file: Path) -> Dict
```

Load YAML file, unified (both single- and multi-paged).

**Arguments**:

- `configuration_file`: the configuration file path.

**Returns**:

the data.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_public_id_from_yaml"></a>

#### get`_`public`_`id`_`from`_`yaml

```python
def get_public_id_from_yaml(configuration_file_path: Path)
```

Get the public id from yaml.

**Arguments**:

- `configuration_file_path`: the path to the config yaml

**Returns**:

public id

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.public_id_in_registry"></a>

#### public`_`id`_`in`_`registry

```python
def public_id_in_registry(type_: str, name: str)
```

Check if a package id is in the registry.

**Arguments**:

- `type_`: the package type
- `name`: the name of the package

**Returns**:

public id

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_all_protocol_spec_ids"></a>

#### get`_`all`_`protocol`_`spec`_`ids

```python
def get_all_protocol_spec_ids() -> Set[PublicId]
```

Get all protocol specification ids.

We return package ids with type "protocol" even though
they are not exactly protocol. The reason is that
they are only used to find clashes with protocol ids.

**Returns**:

a set of package ids.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_all_package_ids"></a>

#### get`_`all`_`package`_`ids

```python
def get_all_package_ids() -> Set[PackageId]
```

Get all the package ids in the local repository.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.get_public_ids_to_update"></a>

#### get`_`public`_`ids`_`to`_`update

```python
def get_public_ids_to_update() -> Set[PackageId]
```

Get all the public ids to be updated.

In particular, a package DOES NOT NEED a version bump if:
- the package is a "scaffold" package;
- the package is no longer present
- the package hasn't change since the last release;
- the public ids of the local package and the package in the registry
  are already the same.

**Returns**:

set of package ids to update

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.minor_version_difference"></a>

#### minor`_`version`_`difference

```python
def minor_version_difference(current_public_id, deployed_public_id) -> int
```

Check the minor version difference.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.replace_aea_fetch_statements"></a>

#### replace`_`aea`_`fetch`_`statements

```python
def replace_aea_fetch_statements(content: str, old_string: str,
                                 new_string: str, type_: str) -> str
```

Replace statements of the type: 'aea fetch <old_string>'.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.replace_aea_add_statements"></a>

#### replace`_`aea`_`add`_`statements

```python
def replace_aea_add_statements(content: str, old_string: str, new_string: str,
                               type_: str) -> str
```

Replace statements of the type: 'aea add <type> <old_string>'.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.replace_type_and_public_id_occurrences"></a>

#### replace`_`type`_`and`_`public`_`id`_`occurrences

```python
def replace_type_and_public_id_occurrences(line: str, old_string: str,
                                           new_string: str, type_: str) -> str
```

Replace the public id whenever the type and the id occur in the same row, and NOT when other type names occur.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.replace_in_yamls"></a>

#### replace`_`in`_`yamls

```python
def replace_in_yamls(content: str, old_public_id, new_public_id,
                     type_: str) -> str
```

Replace the public id in configuration files (also nested in .md files).

1) replace package dependencies:
    |protocols:
    |- author/name:version
    |...
    |- old_string
2) replace in configuration headers:
    |name: package_name
    |author: package_author
    |version: package_version -> bump up
    |type: package_type

**Arguments**:

- `content`: the content
- `old_public_id`: the old public id
- `new_public_id`: the new public id
- `type_`: the type of the package

**Returns**:

replaced content

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.replace_in_protocol_readme"></a>

#### replace`_`in`_`protocol`_`readme

```python
def replace_in_protocol_readme(fp: Path, content: str, old_public_id,
                               new_public_id, type_: str) -> str
```

Replace the version id in the protocol specification in the protcol's README.

That is, bump the version in cases like:
    |name: package_name
    |author: package_author
    |version: package_version -> bump up
    ...

**Arguments**:

- `fp`: path to the file being edited.
- `content`: the content of the file.
- `old_public_id`: the old public id.
- `new_public_id`: the new public id.
- `type_`: the type of the package.

**Returns**:

the new content.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.file_should_be_processed"></a>

#### file`_`should`_`be`_`processed

```python
def file_should_be_processed(content: str, old_public_id) -> bool
```

Check if the file should be processed.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.bump_version_in_yaml"></a>

#### bump`_`version`_`in`_`yaml

```python
def bump_version_in_yaml(configuration_file_path: Path, type_: str,
                         version: str) -> None
```

Bump the package version in the package yaml.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater"></a>

## Updater Objects

```python
class Updater()
```

Package versions updater tool.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.__init__"></a>

#### `__`init`__`

```python
def __init__(ask_version, update_version, replace_by_default, no_interactive,
             context)
```

Init updater.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.check_if_svn_installed"></a>

#### check`_`if`_`svn`_`installed

```python
@staticmethod
def check_if_svn_installed()
```

Check svn tool installed.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.run_hashing"></a>

#### run`_`hashing

```python
@staticmethod
def run_hashing()
```

Run hashes update.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.check_if_running_allowed"></a>

#### check`_`if`_`running`_`allowed

```python
@staticmethod
def check_if_running_allowed()
```

Check if we can run the script.

Script should only be run on a clean branch.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.run"></a>

#### run

```python
def run()
```

Run package versions update process.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.process_packages"></a>

#### process`_`packages

```python
def process_packages(all_package_ids_to_update: Set[PackageId],
                     ambiguous_public_ids: Set[PublicId]) -> None
```

Process the package versions.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.process_package"></a>

#### process`_`package

```python
def process_package(package_id, is_ambiguous: bool) -> None
```

Process a package.

- check version in registry
- make sure, version is exactly one above the one in registry
- change all occurrences in packages/tests/aea/examples/benchmark/docs to new reference
- change yaml version number

**Arguments**:

- `package_id`: the id of the package
- `is_ambiguous`: whether the public id is ambiguous.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.get_new_package_version"></a>

#### get`_`new`_`package`_`version

```python
def get_new_package_version(current_public_id) -> str
```

Get new package version according to command line options provided.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.bump_package_version"></a>

#### bump`_`package`_`version

```python
def bump_package_version(current_public_id,
                         configuration_file_path: Path,
                         type_: str,
                         is_ambiguous: bool = False) -> None
```

Bump the version references of the package in the repo.

Includes, bumping the package itself.

**Arguments**:

- `current_public_id`: the current public id
- `configuration_file_path`: the path to the configuration file
- `type_`: the type of package
- `is_ambiguous`: whether or not the package id is ambiguous

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.Updater.inplace_change"></a>

#### inplace`_`change

```python
def inplace_change(fp: Path, old_public_id, new_public_id, type_: str,
                   is_ambiguous: bool) -> None
```

Replace the occurrence of a string with a new one in the provided file.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_pkg_versions.command"></a>

#### command

```python
@click.command(name="update-pkg-versions")
@click.option(
    "--ask-version",
    "-a",
    is_flag=True,
    help="Ask for every package version interactively",
)
@click.option(
    "--update-minor",
    "update_version",
    flag_value="minor",
    default=None,
    help="Increase minor version",
)
@click.option(
    "--update-patch",
    "update_version",
    flag_value="patch",
    default=None,
    help="Increase patch version",
)
@click.option(
    "--no-interactive",
    "-n",
    is_flag=True,
    help="Don't ask user confirmation for replacement.",
)
@click.option(
    "--context",
    "-C",
    type=int,
    help="The number of above/below rows to display.",
    default=3,
)
@click.option(
    "--replace-by-default",
    "-r",
    is_flag=True,
    help="If --no-interactive is set, apply the replacement (default: False).",
)
def command(ask_version, update_version, replace_by_default, no_interactive,
            context)
```

Update package versions relative to last release.

