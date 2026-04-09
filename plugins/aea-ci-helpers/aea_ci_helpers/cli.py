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

"""CLI entry point for aea-ci-helpers."""

import sys

import click


@click.group()
@click.version_option()
def cli() -> None:
    """AEA CI helper utilities."""


@click.command(name="check-ipfs-pushed")
def check_ipfs_pushed() -> None:
    """Verify all package IPFS hashes from the latest git tag are reachable on the gateway."""
    from aea_ci_helpers.check_ipfs_pushed import (  # pylint: disable=import-outside-toplevel
        check_ipfs_hash_pushed,
        get_file_from_tag,
    )
    import json  # pylint: disable=import-outside-toplevel
    from concurrent.futures import ThreadPoolExecutor  # pylint: disable=import-outside-toplevel

    packages_json = json.loads(get_file_from_tag("packages/packages.json"))["dev"]
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for k, v in packages_json.items():
            click.echo(f"Checking {k}:{v}...")
            futures.append(executor.submit(check_ipfs_hash_pushed, v))
        click.echo("Awaiting for results...")
        future_results = [future.result() for future in futures]
        errors = [r[0] for r in future_results if not r[1]]
        if errors:
            click.echo(f"The following hashes were not found in IPFS registry: {errors}")
            sys.exit(1)
        click.echo("OK")


@click.command(name="check-pyproject")
def check_pyproject() -> None:
    """Verify pyproject.toml and tox.ini dependencies are aligned."""
    from aea_ci_helpers.check_pyproject import (  # pylint: disable=import-outside-toplevel
        check_versions_are_correct,
    )

    if not check_versions_are_correct():
        sys.exit(1)
    click.echo("OK")


@click.command(name="check-pkg-versions")
def check_pkg_versions() -> None:
    """Verify package IDs in documentation match actual package configurations."""
    from aea_ci_helpers.check_pkg_versions import main as check_main  # pylint: disable=import-outside-toplevel

    check_main()


@click.command(name="check-imports")
def check_imports() -> None:
    """Verify all imports are declared as dependencies."""
    from aea_ci_helpers.check_imports import main as check_main  # pylint: disable=import-outside-toplevel

    check_main()


@click.command(name="generate-api-docs")
@click.option("--check", "check_clean", is_flag=True, help="Check docs are up to date without generating.")
def generate_api_docs(check_clean: bool) -> None:
    """Generate API documentation from source."""
    from aea_ci_helpers.generate_api_docs import main as gen_main  # pylint: disable=import-outside-toplevel

    gen_main(check_clean=check_clean)


@click.command(name="generate-pkg-list")
def generate_pkg_list() -> None:
    """Generate markdown table of all packages with their IPFS hashes."""
    from aea_ci_helpers.generate_pkg_list import generate_table  # pylint: disable=import-outside-toplevel

    generate_table()


cli.add_command(check_imports)
cli.add_command(check_ipfs_pushed)
cli.add_command(check_pkg_versions)
cli.add_command(check_pyproject)
cli.add_command(generate_api_docs)
cli.add_command(generate_pkg_list)
