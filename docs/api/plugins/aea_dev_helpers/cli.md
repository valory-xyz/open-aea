<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli"></a>

# plugins.aea-dev-helpers.aea`_`dev`_`helpers.cli

CLI entry point for aea-dev-helpers.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.cli"></a>

#### cli

```python
@click.group()
@click.version_option()
def cli() -> None
```

AEA development and release helper utilities.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.parse_lock_deps_cmd"></a>

#### parse`_`lock`_`deps`_`cmd

```python
@cli.command("parse-lock-deps")
@click.argument("pipfile_lock_path", type=click.Path(exists=True))
@click.option("-o",
              "--output",
              type=click.Path(),
              default=None,
              help="Output file path.")
def parse_lock_deps_cmd(pipfile_lock_path: str, output: Optional[str]) -> None
```

Parse main dependencies from a Pipfile.lock and print in requirements.txt format.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.publish_local_cmd"></a>

#### publish`_`local`_`cmd

```python
@cli.command("publish-local")
@click.option(
    "--package-dir",
    "-pd",
    type=click.Path(exists=True),
    default="./packages",
    help="Path to the packages directory.",
)
def publish_local_cmd(package_dir: str) -> None
```

Publish local packages to an IPFS node.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.update_symlinks_cmd"></a>

#### update`_`symlinks`_`cmd

```python
@cli.command("update-symlinks")
def update_symlinks_cmd() -> None
```

Update symlinks for the project (cross-platform).

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.bump_version_cmd"></a>

#### bump`_`version`_`cmd

```python
@cli.command("bump-version")
@click.option("--new-version", required=True, help="New AEA version string.")
@click.option(
    "-p",
    "--plugin-new-version",
    multiple=True,
    help=
    "Plugin version update in KEY=VALUE format (e.g. aea-ledger-ethereum=2.0.0).",
)
@click.option("--no-fingerprints",
              is_flag=True,
              help="Skip fingerprint updates.")
@click.option("--only-check",
              is_flag=True,
              help="Only check, do not modify files.")
def bump_version_cmd(new_version: str, plugin_new_version: Tuple[str, ...],
                     no_fingerprints: bool, only_check: bool) -> None
```

Bump AEA and plugin versions throughout the codebase.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.deploy_registry_cmd"></a>

#### deploy`_`registry`_`cmd

```python
@cli.command("deploy-registry")
def deploy_registry_cmd() -> None
```

Push all packages to the registry in dependency order.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.update_pkg_versions_cmd"></a>

#### update`_`pkg`_`versions`_`cmd

```python
@cli.command("update-pkg-versions")
@click.pass_context
def update_pkg_versions_cmd(ctx: click.Context) -> None
```

Interactive package version bumping with registry checks.

<a id="plugins.aea-dev-helpers.aea_dev_helpers.cli.update_plugin_versions_cmd"></a>

#### update`_`plugin`_`versions`_`cmd

```python
@cli.command("update-plugin-versions")
@click.option(
    "--update",
    multiple=True,
    required=True,
    help=
    "Plugin update in NAME,VERSION format (e.g. aea-ledger-ethereum,2.0.0).",
)
@click.option("--no-fingerprint",
              is_flag=True,
              help="Skip fingerprint updates.")
def update_plugin_versions_cmd(update: Tuple[str, ...],
                               no_fingerprint: bool) -> None
```

Bump plugin versions and update version specifiers.

