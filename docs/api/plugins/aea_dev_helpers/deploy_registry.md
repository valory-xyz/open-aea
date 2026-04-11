<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.deploy`_`registry

Deploy all new packages to registry.

This module contains the logic originally in ``scripts/deploy_to_registry.py``.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.default_config_file_paths"></a>

#### default`_`config`_`file`_`paths

```python
def default_config_file_paths() -> Generator
```

Get (generator) the default config file paths.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.unified_yaml_load"></a>

#### unified`_`yaml`_`load

```python
def unified_yaml_load(configuration_file: Path) -> Dict
```

Load YAML file, unified (both single- and multi-paged).

**Arguments**:

- `configuration_file`: the configuration file path.

**Returns**:

the data.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.get_public_id_from_yaml"></a>

#### get`_`public`_`id`_`from`_`yaml

```python
def get_public_id_from_yaml(configuration_file: Path)
```

Get the public id from yaml.

**Arguments**:

- `configuration_file`: the path to the config yaml

**Returns**:

public id

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.find_all_packages_ids"></a>

#### find`_`all`_`packages`_`ids

```python
def find_all_packages_ids() -> Set[PackageId]
```

Find all packages ids.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.check_correct_author"></a>

#### check`_`correct`_`author

```python
def check_correct_author(runner: CliRunner) -> None
```

Check whether the correct author is locally configured.

**Arguments**:

- `runner`: the cli runner

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.push_package"></a>

#### push`_`package

```python
def push_package(package_id, runner: CliRunner) -> None
```

Pushes a package (protocol/contract/connection/skill) to registry.

Specifically:
- creates an empty agent project
- adds the relevant package from local 'packages' dir (and its dependencies)
- moves the relevant package out of vendor dir
- pushes the relevant package to registry

**Arguments**:

- `package_id`: the package id
- `runner`: the cli runner

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.publish_agent"></a>

#### publish`_`agent

```python
def publish_agent(package_id, runner: CliRunner) -> None
```

Publishes an agent to registry.

Specifically:
- fetches an agent project from local 'packages' dir (and its dependencies)
- publishes the agent project to registry

**Arguments**:

- `package_id`: the package id
- `runner`: the cli runner

**Returns**:

None

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.check_and_upload"></a>

#### check`_`and`_`upload

```python
def check_and_upload(package_id, runner: CliRunner) -> None
```

Check and upload.

Checks whether a package is missing from registry. If it is missing, uploads it.

**Arguments**:

- `package_id`: the package id
- `runner`: the cli runner

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.upload_new_packages"></a>

#### upload`_`new`_`packages

```python
def upload_new_packages(runner: CliRunner,
                        all_package_ids: Set[PackageId]) -> None
```

Upload new packages.

Checks whether packages are missing from registry in the dependency order.

**Arguments**:

- `runner`: the cli runner
- `all_package_ids`: the set of all package ids to process.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.deploy_registry.main"></a>

#### main

```python
def main() -> None
```

Run the deploy-to-registry workflow.

This is the main entry point intended to be called from a CLI wrapper.

