#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2026 Valory AG
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

"""Script to generate a markdown package table."""

import sys
from pathlib import Path
from typing import Dict

from aea.cli.packages import get_package_manager

COL_WIDTH = 61
PKG_LIST_PATH = Path("docs", "package_list.md")


def get_packages() -> Dict[str, str]:
    """Get packages."""
    data = get_package_manager(Path("packages").relative_to(".")).json
    if "dev" in data:
        return data["dev"]
    return data


def _render_table() -> str:
    """Render the markdown table containing the package list."""
    data = get_packages()

    # Table header
    content = (
        f"| {'Package name'.ljust(COL_WIDTH, ' ')} | {'Package hash'.ljust(COL_WIDTH, ' ')} |\n"
        f"| {'-'*COL_WIDTH} | {'-'*COL_WIDTH} |\n"
    )

    # Table rows
    for package, package_hash in data.items():
        package_cell = package.ljust(COL_WIDTH, " ")
        hash_cell = f"`{package_hash}`".ljust(COL_WIDTH, " ")
        content += f"| {package_cell} | {hash_cell} |\n"

    return content


def generate_table(check: bool = False) -> None:
    """Generates a markdown table containing a package list.

    If `check` is True, compare the freshly-rendered table against the
    existing `docs/package_list.md` and exit non-zero on mismatch instead
    of overwriting it. This lets CI verify the file is in sync without
    having the fix path accidentally clobber unrelated changes.
    """
    content = _render_table()

    if check:
        existing = (
            PKG_LIST_PATH.read_text(encoding="utf-8") if PKG_LIST_PATH.exists() else ""
        )
        if existing != content:
            print(
                f"{PKG_LIST_PATH} is out of sync with packages.json. "
                "Run `aea-ci generate-pkg-list` (or `tox -e lock-packages`) to fix.",
                file=sys.stderr,
            )
            sys.exit(1)
        return

    with open(PKG_LIST_PATH, mode="w", encoding="utf-8") as packages_list:
        packages_list.write(content)


if __name__ == "__main__":
    generate_table()
