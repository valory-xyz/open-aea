<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.update`_`plugin`_`versions

Bump the versions of AEA plugins throughout the code base.

This module contains the logic originally in ``scripts/update_plugin_versions.py``.

Example usage from the CLI wrapper::

    aea-dev update-plugin-versions --update "open-aea-ledger-fetchai,0.2.0" \
        --update "open-aea-ledger-ethereum,0.3.0"

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.update_plugin_setup"></a>

#### update`_`plugin`_`setup

```python
def update_plugin_setup(plugin_name: str, old_version: Version,
                        new_version: Version) -> bool
```

Update plugin setup.py script with new version.

**Arguments**:

- `plugin_name`: the plugin name.
- `old_version`: the old version.
- `new_version`: the new version.

**Returns**:

True if an update has been done, False otherwise.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.process_plugin"></a>

#### process`_`plugin

```python
def process_plugin(plugin_name: str, old_version: Version,
                   new_version: Version) -> bool
```

Process the plugin version.

**Arguments**:

- `plugin_name`: the plugin name.
- `old_version`: the old version.
- `new_version`: the new version.

**Returns**:

True if an update has been done, False otherwise.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.update_plugin_version_specifiers"></a>

#### update`_`plugin`_`version`_`specifiers

```python
def update_plugin_version_specifiers(plugin_name: str, old_version: Version,
                                     new_version: Version) -> bool
```

Update aea_version specifier set in docs.

**Arguments**:

- `plugin_name`: the plugin name.
- `old_version`: the old version.
- `new_version`: the new version.

**Returns**:

True if the update has been done, False otherwise.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.exit_with_message"></a>

#### exit`_`with`_`message

```python
def exit_with_message(message: str, exit_code: int = 1) -> None
```

Exit the program with a message and an exit code.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.get_plugin_names_and_versions"></a>

#### get`_`plugin`_`names`_`and`_`versions

```python
def get_plugin_names_and_versions() -> Dict[str, Version]
```

Get all the plugins names and versions.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.name_version_pair"></a>

#### name`_`version`_`pair

```python
def name_version_pair(s: str) -> Tuple[str, str]
```

Parse a name-version pair.

**Arguments**:

- `s`: the parameter string.

**Returns**:

a pair of string (name, new_version)

<a id="plugins.aea-dev-helpers.aea_dev_helpers.update_plugin_versions.run_update_plugin_versions"></a>

#### run`_`update`_`plugin`_`versions

```python
def run_update_plugin_versions(updates: List[Tuple[str, str]],
                               no_fingerprint: bool = False) -> None
```

Run the update-plugin-versions workflow.

This is the main entry point intended to be called from a CLI wrapper.

**Arguments**:

- `updates`: list of (plugin-name, new-version) tuples.
- `no_fingerprint`: if True, skip fingerprint computation.

