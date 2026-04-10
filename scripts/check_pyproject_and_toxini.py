#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2026 Valory AG
#   Copyright 2018-2021 Fetch.AI Limited
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

"""This script checks that dependencies in tox.ini and pyproject.toml match."""

import configparser
import sys
from typing import Set, Tuple

import tomli
from packaging.requirements import Requirement as BaseRequirement

TOX_INI = "tox.ini"
PYPROJECT_TOML = "pyproject.toml"

# Packages to skip: specified in setup.py as core deps, or not relevant to tox
WHITELIST = {
    "tomte",
    "memory-profiler",
    "apduboy",
    "matplotlib",
    "open-aea-flashbots",
    # Dev deps declared with version ranges in pyproject.toml but pinned
    # exactly in tox.ini — string comparison would always mismatch
    "requests",
    "packaging",
    # Removed from core deps but needed by packages (p2p connections)
    "ecdsa",
    # Replaced by inlined IPFS client
    "ipfshttpclient",
}


class Requirement(BaseRequirement):
    """Requirement with comparison"""

    def __eq__(self, __value: object) -> bool:
        """Compare two objects."""
        return str(self) == str(__value)

    def __hash__(self) -> int:
        """Get hash for object."""
        return hash(self.__str__())


def _parse_poetry_deps(deps: dict) -> list:
    """Parse a Poetry dependency dict into a list of Requirement objects."""
    packages = []
    for name, version in deps.items():
        if name == "python":
            continue
        if isinstance(version, str):
            package_spec = f"{name}{version if version != '*' else ''}"
        else:
            assert isinstance(version, dict)
            extras = (
                ",".join(version.get("extras", [])) if version.get("extras", []) else ""
            )
            extras = f"[{extras}]" if extras else ""
            version_spec = version.get("version") if version.get("version") else ""
            package_spec = f"{name}{extras}{version_spec}"

        packages.append(Requirement(package_spec))
    return packages


def load_pyproject(filename: str = PYPROJECT_TOML) -> Set[Requirement]:
    """Load pyproject.toml dev dependencies."""
    with open(filename, "rb") as f:
        pyproject_data = tomli.load(f)

    poetry = pyproject_data.get("tool", {}).get("poetry", {})

    # Only compare dev dependencies (mirrors old Pipfile [dev-packages] behavior).
    # Core deps in [tool.poetry.dependencies] use ranges for library consumers
    # while tox.ini uses exact pins — they intentionally differ.
    dev_deps = poetry.get("group", {}).get("dev", {}).get("dependencies", {})

    return set(_parse_poetry_deps(dev_deps))


def load_tox_ini(file_name: str = TOX_INI) -> Set[Requirement]:
    """Load tox.ini requirements."""
    config = configparser.ConfigParser()
    config.read(file_name)
    packages = []
    for section in config.values():
        packages.extend(
            list(
                filter(
                    lambda x: (
                        x != "" and not x.startswith("{") and not x.startswith(".")
                    ),
                    section.get("deps", "").splitlines(),
                )
            )
        )
    return set(map(Requirement, packages))


def get_missing_packages() -> Tuple[Set[Requirement], Set[Requirement]]:
    """Get difference in tox.ini and pyproject.toml."""
    in_pyproject = {
        package for package in load_pyproject() if package.name not in WHITELIST
    }
    in_tox = {package for package in load_tox_ini() if package.name not in WHITELIST}

    missing_in_tox = in_pyproject - in_tox
    missing_in_pyproject = in_tox - in_pyproject
    return missing_in_tox, missing_in_pyproject


def check_versions_are_correct() -> bool:
    """Check no missing packages."""
    missing_in_tox, missing_in_pyproject = get_missing_packages()
    if missing_in_tox:
        print("Packages defined in pyproject.toml and not found in tox.ini")
        for i in missing_in_tox:
            print("\t", str(i))

    if missing_in_pyproject:
        print("Packages defined in tox.ini and not found in pyproject.toml")
        for i in missing_in_pyproject:
            print("\t", str(i))

    return not (missing_in_pyproject or missing_in_tox)


if __name__ == "__main__":
    result = check_versions_are_correct()
    if not result:
        sys.exit(1)
    else:
        print("OK")
