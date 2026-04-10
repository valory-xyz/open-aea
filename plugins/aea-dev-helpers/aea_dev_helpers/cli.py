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

"""CLI entry point for aea-dev-helpers."""

from typing import List, Optional, Tuple

import click


@click.group()
@click.version_option()
def cli() -> None:
    """AEA development and release helper utilities."""


@cli.command("parse-lock-deps")
@click.argument("pipfile_lock_path", type=click.Path(exists=True))
@click.option(
    "-o", "--output", type=click.Path(), default=None, help="Output file path."
)
def parse_lock_deps_cmd(pipfile_lock_path: str, output: Optional[str]) -> None:
    """Parse main dependencies from a Pipfile.lock and print in requirements.txt format."""
    from aea_dev_helpers.parse_lock_deps import parse_lock_deps

    parse_lock_deps(pipfile_lock_path, output)


@cli.command("publish-local")
@click.option(
    "--package-dir",
    "-pd",
    type=click.Path(exists=True),
    default="./packages",
    help="Path to the packages directory.",
)
def publish_local_cmd(package_dir: str) -> None:
    """Publish local packages to an IPFS node."""
    from aea_dev_helpers.publish_local import publish_local

    publish_local(package_dir)


@cli.command("update-symlinks")
def update_symlinks_cmd() -> None:
    """Update symlinks for the project (cross-platform)."""
    from aea_dev_helpers.update_symlinks import (  # pylint: disable=import-outside-toplevel
        update_symlinks,
    )

    update_symlinks()


@cli.command("bump-version")
@click.option("--new-version", required=True, help="New AEA version string.")
@click.option(
    "-p",
    "--plugin-new-version",
    multiple=True,
    help="Plugin version update in KEY=VALUE format (e.g. aea-ledger-ethereum=2.0.0).",
)
@click.option("--no-fingerprints", is_flag=True, help="Skip fingerprint updates.")
@click.option("--only-check", is_flag=True, help="Only check, do not modify files.")
def bump_version_cmd(
    new_version: str,
    plugin_new_version: Tuple[str, ...],
    no_fingerprints: bool,
    only_check: bool,
) -> None:
    """Bump AEA and plugin versions throughout the codebase."""
    from aea_dev_helpers.bump_version import (  # pylint: disable=import-outside-toplevel
        run_bump,
    )

    plugin_map = {}
    for pnv in plugin_new_version:
        key, _, value = pnv.partition("=")
        if not value:
            raise click.BadParameter(f"Expected KEY=VALUE format, got: {pnv}")
        plugin_map[key] = value
    run_bump(new_version, plugin_map, no_fingerprints, only_check)


@cli.command("deploy-registry")
def deploy_registry_cmd() -> None:
    """Push all packages to the registry in dependency order."""
    from aea_dev_helpers.deploy_registry import (
        main as deploy_main,  # pylint: disable=import-outside-toplevel
    )

    deploy_main()


@cli.command("update-pkg-versions")
@click.pass_context
def update_pkg_versions_cmd(ctx: click.Context) -> None:
    """Interactive package version bumping with registry checks."""
    from aea_dev_helpers.update_pkg_versions import (  # pylint: disable=import-outside-toplevel
        command,
    )

    # Delegate to the existing click command from the migrated module
    ctx.invoke(command)


@cli.command("update-plugin-versions")
@click.option(
    "--update",
    multiple=True,
    required=True,
    help="Plugin update in NAME,VERSION format (e.g. aea-ledger-ethereum,2.0.0).",
)
@click.option("--no-fingerprint", is_flag=True, help="Skip fingerprint updates.")
def update_plugin_versions_cmd(
    update: Tuple[str, ...],
    no_fingerprint: bool,
) -> None:
    """Bump plugin versions and update version specifiers."""
    from aea_dev_helpers.update_plugin_versions import (  # pylint: disable=import-outside-toplevel
        run_update_plugin_versions,
    )

    updates = []
    for u in update:
        parts = u.split(",", 1)
        if len(parts) != 2:
            raise click.BadParameter(f"Expected NAME,VERSION format, got: {u}")
        updates.append((parts[0], parts[1]))
    run_update_plugin_versions(updates, no_fingerprint)
