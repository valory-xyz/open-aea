<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli"></a>

# plugins.aea-ci-helpers.aea`_`ci`_`helpers.cli

CLI entry point for aea-ci-helpers.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.cli"></a>

#### cli

```python
@click.group()
@click.version_option()
def cli() -> None
```

AEA CI helper utilities.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.check_ipfs_pushed"></a>

#### check`_`ipfs`_`pushed

```python
@click.command(name="check-ipfs-pushed")
def check_ipfs_pushed() -> None
```

Verify all package IPFS hashes from the latest git tag are reachable on the gateway.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.check_pyproject"></a>

#### check`_`pyproject

```python
@click.command(name="check-pyproject")
def check_pyproject() -> None
```

Verify pyproject.toml and tox.ini dependencies are aligned.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.check_pkg_versions"></a>

#### check`_`pkg`_`versions

```python
@click.command(name="check-pkg-versions")
def check_pkg_versions() -> None
```

Verify package IDs in documentation match actual package configurations.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.check_imports"></a>

#### check`_`imports

```python
@click.command(name="check-imports")
def check_imports() -> None
```

Verify all imports are declared as dependencies.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.generate_api_docs"></a>

#### generate`_`api`_`docs

```python
@click.command(name="generate-api-docs")
@click.option("--check",
              "check_clean",
              is_flag=True,
              help="Check docs are up to date without generating.")
def generate_api_docs(check_clean: bool) -> None
```

Generate API documentation from source.

<a id="plugins.aea-ci-helpers.aea_ci_helpers.cli.generate_pkg_list"></a>

#### generate`_`pkg`_`list

```python
@click.command(name="generate-pkg-list")
def generate_pkg_list() -> None
```

Generate markdown table of all packages with their IPFS hashes.

