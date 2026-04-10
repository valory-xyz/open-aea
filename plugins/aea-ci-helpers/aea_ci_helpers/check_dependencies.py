# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2023-2026 Valory AG
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
Check that repository dependency files (Pipfile, tox.ini, pyproject.toml) are
consistent with the package-level dependencies declared inside ``packages/``.

All ``aea.*`` imports are lazy (performed inside the functions that need them)
so that this module can be imported even when the ``aea`` package is not
installed.
"""

import itertools
import logging
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from typing import OrderedDict as OrderedDictType
from typing import Tuple, cast

import click
import toml

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

    ignore = [
        "open-aea-ledger-cosmos",
        "open-aea-ledger-ethereum",
        "open-aea-ledger-fetchai",
        "open-aea-flashbots",
        "open-aea-flashbots",
        "tomte",
    ]

    def __init__(
        self,
        sources: List[str],
        packages: OrderedDictType[str, Any],
        dev_packages: OrderedDictType[str, Any],
        file: Path,
    ) -> None:
        """Initialize object."""
        self.sources = sources
        self.packages = packages
        self.dev_packages = dev_packages
        self.file = file

    def __iter__(self) -> Iterator:
        """Iterate dependencies as Dependency objects."""
        for name, dependency in itertools.chain(
            self.packages.items(), self.dev_packages.items()
        ):
            if name.startswith("comment_") or name in self.ignore:
                continue
            yield dependency

    def update(self, dependency: Any) -> None:
        """Update dependency specifier."""
        if dependency.name in self.ignore:
            return
        if dependency.name in self.packages:
            if dependency.version == "":
                return
            self.packages[dependency.name] = dependency
        else:
            self.dev_packages[dependency.name] = dependency

    def check(self, dependency: Any) -> Tuple[Optional[str], int]:
        """Check dependency specifier."""
        if dependency.name in self.ignore:
            return None, 0

        if dependency.name in self.packages:
            expected = self.packages[dependency.name]
            if expected != dependency:
                return (
                    f"in Pipfile {expected.get_pip_install_args()[0]}; "
                    f"got {dependency.get_pip_install_args()[0]}"
                ), logging.WARNING
            return None, 0

        if dependency.name not in self.dev_packages:
            return f"{dependency.name} not found in Pipfile", logging.ERROR

        expected = self.dev_packages[dependency.name]
        if expected != dependency:
            return (
                f"in Pipfile {expected.get_pip_install_args()[0]}; "
                f"got {dependency.get_pip_install_args()[0]}"
            ), logging.WARNING

        return None, 0

    @classmethod
    def parse(
        cls, content: str
    ) -> Tuple[List[str], OrderedDictType[str, OrderedDictType[str, Any]]]:
        """Parse from string."""
        from aea.configurations.data_types import (  # pylint: disable=import-outside-toplevel
            Dependency,
        )

        sources: List[str] = []
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
                while len(lines) > 0:
                    line = lines.pop(0).strip()
                    if line == "":
                        break
                    if line.startswith("#"):
                        sections[section][f"comment_{comments}"] = line
                        comments += 1
                    else:
                        dep = Dependency.from_pipfile_string(line)
                        sections[section][dep.name] = dep
        return sources, sections

    def compile(self) -> str:
        """Compile to Pipfile string."""
        content = ""
        for source in self.sources:
            content += source + "\n"

        content += "[packages]\n"
        for package, dep in self.packages.items():
            if package.startswith("comment"):
                content += str(dep) + "\n"
            else:
                content += dep.to_pipfile_string() + "\n"

        content += "\n[dev-packages]\n"
        for package, dep in self.dev_packages.items():
            if package.startswith("comment"):
                content += str(dep) + "\n"
            else:
                content += dep.to_pipfile_string() + "\n"
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
        self.extra: Dict[str, Any] = {}

    def __iter__(self) -> Iterator:
        """Iter dependencies."""
        for obj in self.dependencies.values():
            yield obj["dep"]

    def update(self, dependency: Any) -> None:
        """Update dependency specifier."""
        if dependency.name in self.skip:
            return
        if dependency.name in self.dependencies:
            if dependency.version == "":
                return
            self.dependencies[dependency.name]["dep"] = dependency
            return
        self.extra[dependency.name] = dependency

    def check(self, dependency: Any) -> Tuple[Optional[str], int]:
        """Check dependency specifier."""
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
        from aea.configurations.data_types import (  # pylint: disable=import-outside-toplevel
            Dependency,
        )

        deps: Dict[str, Dict[str, Any]] = {}
        lines = content.split("\n")
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
            replace = "    " + cast(Any, obj["dep"]).get_pip_install_args()[0]
            content = re.sub(obj["original"], replace, content)

        if len(self.extra) > 0:
            content = self._include_extra(content=content)

        self.file.write_text(content, encoding="utf-8")


class PyProjectToml:
    """Class to represent pyproject.toml file."""

    ignore = [
        "python",
    ]

    def __init__(
        self,
        dependencies: OrderedDictType[str, Any],
        config: Dict[str, Dict],
        file: Path,
    ) -> None:
        """Initialize object."""
        self.dependencies = dependencies
        self.config = config
        self.file = file

    def __iter__(self) -> Iterator:
        """Iterate dependencies as Dependency objects."""
        for dependency in self.dependencies.values():
            if dependency.name not in self.ignore:
                yield dependency

    def update(self, dependency: Any) -> None:
        """Update dependency specifier."""
        if dependency.name in self.ignore:
            return
        if dependency.name in self.dependencies and dependency.version == "":
            return
        self.dependencies[dependency.name] = dependency

    def check(self, dependency: Any) -> Tuple[Optional[str], int]:
        """Check dependency specifier."""
        if dependency.name in self.ignore:
            return None, 0

        if dependency.name not in self.dependencies:
            return f"{dependency.name} not found in pyproject.toml", logging.ERROR

        expected = self.dependencies[dependency.name]
        if expected != dependency:
            return (
                f"in pyproject.toml {expected.get_pip_install_args()[0]}; "
                f"got {dependency.get_pip_install_args()[0]}"
            ), logging.WARNING

        return None, 0

    @classmethod
    def load(cls, pyproject_path: Path) -> Optional["PyProjectToml"]:
        """Load pyproject.yaml dependencies."""
        from aea.configurations.data_types import (  # pylint: disable=import-outside-toplevel
            Dependency,
        )

        config = toml.load(pyproject_path)
        dependencies: OrderedDictType[str, Any] = OrderedDict()
        try:
            config["tool"]["poetry"]["dependencies"]
        except KeyError:
            return None
        for name, version in config["tool"]["poetry"]["dependencies"].items():
            if isinstance(version, str):
                dependencies[name] = Dependency(
                    name=name,
                    version=version.replace("^", "==") if version != "*" else "",
                )
                continue
            data = cast(Dict, version)
            if "extras" in data:
                version = data["version"]
                if re.match(r"^\d", version):
                    version = f"=={version}"
                dependencies[name] = Dependency(
                    name=name,
                    version=version,
                    extras=data["extras"],
                )
                continue

        return cls(
            dependencies=dependencies,
            config=config,
            file=pyproject_path,
        )

    def dump(self) -> None:
        """Dump to file."""
        self.config["tool"]["poetry"]["dependencies"] = {
            package.name: package.version if package.version != "" else "*"
            for package in self.dependencies.values()
        }
        with self.file.open("w") as fp:
            toml.dump(self.config, fp)


def load_packages_dependencies(packages_dir: Path) -> List:
    """Return a list of package dependencies."""
    from aea.package_manager.base import (  # pylint: disable=import-outside-toplevel
        load_configuration,
    )
    from aea.package_manager.v1 import (  # pylint: disable=import-outside-toplevel
        PackageManagerV1,
    )

    package_manager = PackageManagerV1.from_dir(packages_dir=packages_dir)
    dependencies: Dict[str, Any] = {}
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
                    f"Non-matching dependency versions for {key}: "
                    f"{value} vs {dependencies[key]}"
                )

    return list(dependencies.values())


def update_dependencies(
    packages_dependencies: List,
    tox: ToxFile,
    pipfile: Optional[Pipfile] = None,
    pyproject: Optional[PyProjectToml] = None,
) -> None:
    """Update dependencies across all config files."""

    if pipfile is not None:
        for dependency in packages_dependencies:
            pipfile.update(dependency=dependency)

        for dependency in pipfile:
            tox.update(dependency=dependency)

        for dependency in tox:
            pipfile.update(dependency=dependency)

        pipfile.dump()

    if pyproject is not None:
        for dependency in packages_dependencies:
            pyproject.update(dependency=dependency)

        for dependency in pyproject:
            tox.update(dependency=dependency)

        for dependency in tox:
            pyproject.update(dependency=dependency)

        pyproject.dump()

    tox.write()


def check_dependencies(
    packages_dependencies: List,
    tox: ToxFile,
    pipfile: Optional[Pipfile] = None,
    pyproject: Optional[PyProjectToml] = None,
) -> None:
    """Check dependencies across all config files."""

    fail_check = 0

    if pipfile is not None:
        print("Comparing dependencies from Pipfile and packages")
        for dependency in packages_dependencies:
            error, level = pipfile.check(dependency=dependency)
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

    if pyproject is not None:
        print("Comparing dependencies from pyproject.toml and packages")
        for dependency in packages_dependencies:
            error, level = pyproject.check(dependency=dependency)
            if error is not None:
                logging.log(level=level, msg=error)
                fail_check = level or fail_check

        print("Comparing dependencies from pyproject.toml and tox")
        for dependency in pyproject:
            error, level = tox.check(dependency=dependency)
            if error is not None:
                logging.log(level=level, msg=error)
                fail_check = level or fail_check

        print("Comparing dependencies from tox and pyproject.toml")
        for dependency in tox:
            error, level = pyproject.check(dependency=dependency)
            if error is not None:
                logging.log(level=level, msg=error)
                fail_check = level or fail_check

    print("Comparing dependencies from tox and packages")
    for dependency in packages_dependencies:
        error, level = tox.check(dependency=dependency)
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
