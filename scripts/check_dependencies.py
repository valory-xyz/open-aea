#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2023 Valory AG
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
"""
This script checks that the pipfile of the repository meets the requirements.

In particular:
- Avoid the usage of "*"

It is assumed the script is run from the repository root.
"""

import logging
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from typing import OrderedDict as OrderedDictType
from typing import Tuple, cast

import click

from aea.configurations.data_types import Dependency
from aea.package_manager.base import load_configuration
from aea.package_manager.v1 import PackageManagerV1


ANY_SPECIFIER = "*"


class PathArgument(click.Path):
    """Path parameter for CLI."""

    def convert(
        self, value: Any, param: Optional[click.Parameter], ctx: Optional[click.Context]
    ) -> Optional[Path]:
        """Convert path string to `pathlib.Path`"""
        path_string = super().convert(value, param, ctx)
        return None if path_string is None else Path(path_string)


class Pipfile:
    """Class to represent Pipfile config."""

    skip = [
        "open-aea-ledger-cosmos",
        "open-aea-ledger-ethereum",
        "open-aea-ledger-fetchai",
        "open-aea-flashbots",
    ]

    def __init__(
        self,
        sources: List[str],
        packages: OrderedDictType[str, str],
        dev_packages: OrderedDictType[str, str],
        file: Path,
    ) -> None:
        """Initialize object."""
        self.sources = sources
        self.packages = packages
        self.dev_packages = dev_packages
        self.file = file

    @staticmethod
    def as_dependency(name: str, version: str) -> Dependency:
        """Returns the dependency as aea.configurations.data_types.Dependency object"""
        return Dependency(name=name, version=version.replace('"', "").replace("*", ""))

    def __iter__(self) -> Iterator[Dependency]:
        """Iterate dependencies as from aea.configurations.data_types.Dependency object."""
        for package, version in self.packages.items():
            if package.startswith("comment_"):
                continue
            if package == "tomte":
                continue
            yield self.as_dependency(name=package, version=version)

        for package, version in self.dev_packages.items():
            if package.startswith("comment_"):
                continue
            if package == "tomte":
                continue
            yield self.as_dependency(name=package, version=version)

    def update(self, dependency: Dependency) -> None:
        """Update dependency specifier"""
        if dependency.name in self.skip:
            return
        if dependency.name in self.packages:
            if dependency.version == "":
                return
            self.packages[dependency.name] = f'"{dependency.version}"'
        else:
            self.dev_packages[dependency.name] = f'"{dependency.version}"'

    def check(self, dependency: Dependency) -> Tuple[Optional[str], int]:
        """Check dependency specifier"""
        if dependency.name in self.skip:
            return None, 0

        if dependency.name in self.packages:
            expected = self.as_dependency(
                name=dependency.name, version=self.packages[dependency.name]
            )
            if expected != dependency:
                return (
                    f"in Pipfile {expected.get_pip_install_args()[0]}; "
                    f"got {dependency.get_pip_install_args()[0]}"
                ), logging.WARNING
            return None, 0

        if dependency.name not in self.dev_packages:
            return f"{dependency.name} not found in Pipfile", logging.ERROR

        expected = self.as_dependency(
            name=dependency.name, version=self.dev_packages[dependency.name]
        )
        if expected != dependency:
            return (
                f"in Pipfile {expected.get_pip_install_args()[0]}; "
                f"got {dependency.get_pip_install_args()[0]}"
            ), logging.WARNING

        return None, 0

    @classmethod
    def parse(
        cls, content: str
    ) -> Tuple[List[str], OrderedDictType[str, OrderedDictType[str, str]]]:
        """Parse from string."""
        sources = []
        sections: OrderedDictType = OrderedDict()
        lines = content.split("\n")
        comments = 0
        while len(lines) > 0:
            line = lines.pop(0)
            if "[[source]]" in line:
                source = line + "\n"
                while True:
                    line = lines.pop(0)
                    if line == "":
                        break
                    source += line + "\n"
                sources.append(source)
            if "[dev-packages]" in line or "[packages]" in line:
                section = line
                sections[section] = OrderedDict()
                while True:
                    line = lines.pop(0).strip()
                    if line == "":
                        break
                    if line.startswith("#"):
                        sections[section][f"comment_{comments}"] = line
                        comments += 1
                    else:
                        package, *version = line.split(" = ")
                        sections[section][package] = " = ".join(version)
        return sources, sections

    def compile(self) -> str:
        """Compile to Pipfile string."""
        content = ""
        for source in self.sources:
            content += source + "\n"

        content += "[packages]\n"
        for package, version in self.packages.items():
            if package.startswith("comment"):
                content += version + "\n"
            else:
                if version == '""':
                    version = '"*"'
                content += f"{package} = {version}\n"

        content += "\n[dev-packages]\n"
        for package, version in self.dev_packages.items():
            if package.startswith("comment"):
                content += version + "\n"
            else:
                if version == '""':
                    version = '"*"'
                content += f"{package} = {version}\n"

        return content

    @classmethod
    def load(cls, file: Path) -> "Pipfile":
        """Load from file."""
        sources, sections = cls.parse(
            content=file.read_text(encoding="utf-8"),
        )
        return cls(
            sources=sources,
            packages=sections.get("[packages]", OrderedDict()),
            dev_packages=sections.get("[dev-packages]", OrderedDict()),
            file=file,
        )

    def dump(self) -> None:
        """Write to Pipfile."""
        self.file.write_text(self.compile(), encoding="utf-8")


class ToxFile:
    """Class to represent tox.ini file."""

    skip = [
        "open-aea-ledger-cosmos",
        "open-aea-ledger-ethereum",
        "open-aea-ledger-fetchai",
    ]

    def __init__(
        self,
        dependencies: Dict[str, Dict[str, Any]],
        file: Path,
    ) -> None:
        """Initialize object."""
        self.dependencies = dependencies
        self.file = file
        self.extra: Dict[str, Dependency] = {}

    def __iter__(self) -> Iterator[Dependency]:
        """Iter dependencies."""
        for obj in self.dependencies.values():
            yield obj["dep"]

    def update(self, dependency: Dependency) -> None:
        """Update dependency specifier"""
        if dependency.name in self.skip:
            return
        if dependency.name in self.dependencies:
            if dependency.version == "":
                return
            self.dependencies[dependency.name]["dep"] = dependency
            return
        self.extra[dependency.name] = dependency

    def check(self, dependency: Dependency) -> Tuple[Optional[str], int]:
        """Check dependency specifier"""
        if dependency.name in self.skip:
            return None, 0

        if dependency.name in self.dependencies:
            expected = self.dependencies[dependency.name]["dep"]
            if expected != dependency:
                return (
                    f"in tox.ini {expected.get_pip_install_args()[0]}; "
                    f"got {dependency.get_pip_install_args()[0]}"
                ), logging.WARNING
            return None, 0
        return f"{dependency.name} not found in tox.ini", logging.ERROR

    @classmethod
    def parse(cls, content: str) -> Dict[str, Dict[str, Any]]:
        """Parse file content."""
        lines = content.split("\n")
        deps = {}
        while len(lines) > 0:
            line = lines.pop(0)
            if line.startswith("deps"):
                while True:
                    line = lines.pop(0)
                    if not line.startswith("    "):
                        break
                    if (
                        line.startswith("    {")
                        or line.startswith("    ;")
                        or line.strip() == ""
                        or "tomte" in line
                    ):
                        continue
                    dep = Dependency.from_string(line.lstrip())
                    deps[dep.name] = {
                        "original": line,
                        "dep": dep,
                    }
        return deps

    @classmethod
    def load(cls, file: Path) -> "ToxFile":
        """Load tox.ini file."""
        content = file.read_text(encoding="utf-8")
        dependencies = cls.parse(content=content)
        return cls(
            dependencies=dependencies,
            file=file,
        )

    def _include_extra(self, content: str) -> str:
        """Include extra dependencies."""
        lines = content.split("\n")
        extra = []
        for dep in self.extra.values():
            extra.append(f"    {dep.get_pip_install_args()[0]}")

        if "[extra-deps]" in lines:
            start_idx = lines.index("[extra-deps]") + 2
            end_idx = lines.index("; end-extra")
            extra = list(sorted(set(extra + lines[start_idx:end_idx])))
            lines = lines[:start_idx] + extra + lines[end_idx:]
        else:
            idx = lines.index("[testenv]")
            lines = [
                *lines[:idx],
                "[extra-deps]",
                "deps = ",
                *list(sorted(extra)),
                "; end-extra\n",
                *lines[idx:],
            ]

        return "\n".join(lines)

    def write(self) -> None:
        """Dump config."""
        content = self.file.read_text(encoding="utf-8")
        for obj in self.dependencies.values():
            replace = "    " + cast(Dependency, obj["dep"]).get_pip_install_args()[0]
            content = re.sub(obj["original"], replace, content)

        if len(self.extra) > 0:
            content = self._include_extra(content=content)

        self.file.write_text(content, encoding="utf-8")


def load_packages_dependencies(packages_dir: Path) -> List[Dependency]:
    """Returns a list of package dependencies."""
    package_manager = PackageManagerV1.from_dir(packages_dir=packages_dir)
    dependencies: Dict[str, Dependency] = {}
    for package in package_manager.iter_dependency_tree():
        if package.package_type.value == "service":
            continue
        _dependencies = load_configuration(  # type: ignore
            package_type=package.package_type,
            package_path=package_manager.package_path_from_package_id(
                package_id=package
            ),
        ).dependencies
        for key, value in _dependencies.items():
            if key not in dependencies:
                dependencies[key] = value
            else:
                if value.version == "":
                    continue
                if dependencies[key].version == "":
                    dependencies[key] = value
                if value == dependencies[key]:
                    continue
                print(
                    f"Non-matching dependency versions for {key}: {value} vs {dependencies[key]}"
                )

    return list(dependencies.values())


def _update(
    tox: ToxFile,
    pipfile: Pipfile,
    packages_dependencies: List[Dependency],
) -> None:
    """Update dependencies."""

    for dependency in packages_dependencies:
        pipfile.update(dependency=dependency)

    for dependency in pipfile:
        tox.update(dependency=dependency)

    for dependency in tox:
        pipfile.update(dependency=dependency)

    pipfile.dump()
    tox.write()


def _check(
    tox: ToxFile,
    pipfile: Pipfile,
    packages_dependencies: List[Dependency],
) -> None:
    """Update dependencies."""

    fail_check = 0

    print("Comparing dependencies from Pipfile and packages")
    for dependency in packages_dependencies:
        error, level = pipfile.check(dependency=dependency)
        if error is not None:
            logging.log(level=level, msg=error)
            fail_check = level or fail_check

    print("Comparing dependencies from tox and packages")
    for dependency in packages_dependencies:
        error, level = tox.check(dependency=dependency)
        if error is not None:
            logging.log(level=level, msg=error)
            fail_check = level or fail_check

    print("Comparing dependencies from tox and Pipfile")
    for dependency in pipfile:
        error, level = tox.check(dependency=dependency)
        if error is not None:
            logging.log(level=level, msg=error)
            fail_check = level or fail_check

    print("Comparing dependencies from Pipfile and tox")
    for dependency in tox:
        error, level = pipfile.check(dependency=dependency)
        if error is not None:
            logging.log(level=level, msg=error)
            fail_check = level or fail_check

    if fail_check == logging.ERROR:
        print("Dependencies check failed")
        sys.exit(1)

    if fail_check == logging.WARNING:
        print("Please address warnings to avoid errors")
        sys.exit(0)

    print("No issues found")


@click.command(name="dm")
@click.option(
    "--check",
    is_flag=True,
    help="Perform dependency checks.",
)
@click.option(
    "--packages",
    "packages_dir",
    type=PathArgument(
        exists=True,
        file_okay=False,
        dir_okay=True,
    ),
    help="Path of the packages directory.",
)
@click.option(
    "--tox",
    "tox_path",
    type=PathArgument(
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    help="Tox config path.",
)
@click.option(
    "--pipfile",
    "pipfile_path",
    type=PathArgument(
        exists=True,
        file_okay=True,
        dir_okay=False,
    ),
    help="Pipfile path.",
)
def main(
    check: bool = False,
    packages_dir: Optional[Path] = None,
    tox_path: Optional[Path] = None,
    pipfile_path: Optional[Path] = None,
) -> None:
    """Check dependencies across packages, tox.ini, pyproject.toml and setup.py"""

    logging.basicConfig(format="- %(levelname)s: %(message)s")

    tox_path = tox_path or Path.cwd() / "tox.ini"
    tox = ToxFile.load(tox_path)

    pipfile_path = pipfile_path or Path.cwd() / "Pipfile"
    pipfile = Pipfile.load(pipfile_path)

    packages_dir = packages_dir or Path.cwd() / "packages"
    packages_dependencies = load_packages_dependencies(packages_dir=packages_dir)

    if check:
        return _check(
            tox=tox,
            pipfile=pipfile,
            packages_dependencies=packages_dependencies,
        )

    return _update(
        tox=tox,
        pipfile=pipfile,
        packages_dependencies=packages_dependencies,
    )


if __name__ == "__main__":
    main()
