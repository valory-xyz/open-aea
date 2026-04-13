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
from typing import Optional

import click


@click.group()
@click.version_option()
def cli() -> None:
    """AEA CI helper utilities."""


@click.command(name="check-ipfs-pushed")
def check_ipfs_pushed() -> None:
    """Verify all package IPFS hashes from the latest git tag are reachable on the gateway."""
    import json  # pylint: disable=import-outside-toplevel
    from concurrent.futures import (  # pylint: disable=import-outside-toplevel
        ThreadPoolExecutor,
    )

    from aea_ci_helpers.check_ipfs_pushed import (  # pylint: disable=import-outside-toplevel
        check_ipfs_hash_pushed,
        get_file_from_tag,
    )

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
            click.echo(
                f"The following hashes were not found in IPFS registry: {errors}"
            )
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
    from pathlib import Path  # pylint: disable=import-outside-toplevel

    from aea_ci_helpers.check_pkg_versions import (  # pylint: disable=import-outside-toplevel
        PackageIdNotFound,
        check_file,
        handle_package_not_found,
    )

    docs_files = Path("docs").glob("**/*.md")
    try:
        for file_ in docs_files:
            click.echo(f"Processing {file_}")
            check_file(file_)
    except PackageIdNotFound as e:
        handle_package_not_found(e)
        sys.exit(1)

    click.echo("Done!")
    sys.exit(0)


@click.command(name="check-imports")
def check_imports() -> None:
    """Verify all imports are declared as dependencies."""
    from aea_ci_helpers.check_imports import (  # pylint: disable=import-outside-toplevel
        CheckTool,
    )

    CheckTool.run()


@click.command(name="generate-api-docs")
@click.option(
    "--check",
    "check_clean",
    is_flag=True,
    help="Check docs are up to date without generating.",
)
def generate_api_docs(check_clean: bool) -> None:
    """Generate API documentation from source."""
    import shutil  # pylint: disable=import-outside-toplevel

    from aea_ci_helpers.generate_api_docs import (
        generate_api_docs as gen_docs,  # pylint: disable=import-outside-toplevel
    )

    from aea.helpers.git import (  # pylint: disable=import-outside-toplevel
        check_working_tree_is_dirty,
    )

    res = shutil.which("pydoc-markdown")
    if res is None:
        click.echo(
            "pydoc-markdown not found. Install it: pip install pydoc-markdown==3.3.0"
        )
        sys.exit(1)

    gen_docs()

    if check_clean:
        is_clean = check_working_tree_is_dirty()
        if not is_clean:
            sys.exit(1)


@click.command(name="generate-pkg-list")
@click.option(
    "--check",
    is_flag=True,
    help="Verify docs/package_list.md is in sync instead of overwriting it.",
)
def generate_pkg_list(check: bool) -> None:
    """Generate markdown table of all packages with their IPFS hashes."""
    from aea_ci_helpers.generate_pkg_list import (  # pylint: disable=import-outside-toplevel
        generate_table,
    )

    generate_table(check=check)


@click.command(name="check-doc-hashes")
@click.option("--fix", is_flag=True, help="Fix hashes instead of checking.")
def check_doc_hashes(fix: bool) -> None:
    """Validate and fix IPFS hashes in documentation."""
    from aea_ci_helpers.check_doc_hashes import (  # pylint: disable=import-outside-toplevel
        check_ipfs_hashes,
    )

    check_ipfs_hashes(fix=fix)


@click.command(name="check-dependencies")
@click.option(
    "--check",
    "do_check",
    is_flag=True,
    help="Perform dependency checks.",
)
@click.option(
    "--packages",
    "packages_dir",
    type=click.Path(exists=True, file_okay=False, dir_okay=True),
    default=None,
    help="Path of the packages directory.",
)
@click.option(
    "--tox",
    "tox_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    default=None,
    help="Tox config path.",
)
@click.option(
    "--pipfile",
    "pipfile_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    default=None,
    help="Pipfile path.",
)
@click.option(
    "--pyproject",
    "pyproject_path",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    default=None,
    help="pyproject.toml path.",
)
def check_dependencies_cmd(
    do_check: bool = False,
    packages_dir: Optional[str] = None,
    tox_path: Optional[str] = None,
    pipfile_path: Optional[str] = None,
    pyproject_path: Optional[str] = None,
) -> None:
    """Check dependencies across packages, tox.ini, pyproject.toml and Pipfile."""
    import logging  # pylint: disable=import-outside-toplevel
    from pathlib import Path  # pylint: disable=import-outside-toplevel

    from aea_ci_helpers.check_dependencies import (  # pylint: disable=import-outside-toplevel
        Pipfile,
        PyProjectToml,
        ToxFile,
        check_dependencies,
        load_packages_dependencies,
        update_dependencies,
    )

    logging.basicConfig(format="- %(levelname)s: %(message)s")

    _tox_path = Path(tox_path) if tox_path else Path.cwd() / "tox.ini"
    tox = ToxFile.load(_tox_path)

    _pipfile_path = Path(pipfile_path) if pipfile_path else Path.cwd() / "Pipfile"
    pipfile = Pipfile.load(_pipfile_path) if _pipfile_path.exists() else None

    _pyproject_path = (
        Path(pyproject_path) if pyproject_path else Path.cwd() / "pyproject.toml"
    )
    pyproject = (
        PyProjectToml.load(_pyproject_path) if _pyproject_path.exists() else None
    )

    _packages_dir = Path(packages_dir) if packages_dir else Path.cwd() / "packages"
    packages_deps = load_packages_dependencies(packages_dir=_packages_dir)

    if do_check:
        return check_dependencies(
            tox=tox,
            pipfile=pipfile,
            pyproject=pyproject,
            packages_dependencies=packages_deps,
        )

    return update_dependencies(
        tox=tox,
        pipfile=pipfile,
        pyproject=pyproject,
        packages_dependencies=packages_deps,
    )


cli.add_command(check_dependencies_cmd)
cli.add_command(check_doc_hashes)
cli.add_command(check_imports)
cli.add_command(check_ipfs_pushed)
cli.add_command(check_pkg_versions)
cli.add_command(check_pyproject)
cli.add_command(generate_api_docs)
cli.add_command(generate_pkg_list)
