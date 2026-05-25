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

"""Check repository dependency consistency.

Check that repository dependency files (Pipfile, tox.ini, pyproject.toml) are
consistent with the package-level dependencies declared inside ``packages/``.

"""

import itertools
import logging
import re
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional
from typing import OrderedDict as OrderedDictType
from typing import Set, Tuple, cast

import click
import tomli_w

try:
    import tomllib  # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore[no-redef]

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

    ignore = [
        "open-aea-ledger-cosmos",
        "open-aea-ledger-ethereum",
        "open-aea-ledger-fetchai",
        "tomte",
    ]

    def __init__(
        self,
        sources: List[str],
        packages: OrderedDictType[str, Dependency],
        dev_packages: OrderedDictType[str, Dependency],
        file: Path,
    ) -> None:
        """Initialize object."""
        self.sources = sources
        self.packages = packages
        self.dev_packages = dev_packages
        self.file = file

    def __iter__(self) -> Iterator[Dependency]:
        """Iterate dependencies as Dependency objects."""
        for name, dependency in itertools.chain(
            self.packages.items(), self.dev_packages.items()
        ):
            if name.startswith("comment_") or name in self.ignore:
                continue
            yield dependency

    def update(self, dependency: Dependency) -> None:
        """Update dependency specifier."""
        if dependency.name in self.ignore:
            return
        if dependency.name in self.packages:
            if dependency.version == "":
                return
            self.packages[dependency.name] = dependency
        else:
            self.dev_packages[dependency.name] = dependency

    def check(self, dependency: Dependency) -> Tuple[Optional[str], int]:
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
    ) -> Tuple[List[str], OrderedDictType[str, OrderedDictType[str, Dependency]]]:
        """Parse from string."""
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
        self.extra: Dict[str, Dependency] = {}

    def __iter__(self) -> Iterator[Dependency]:
        """Iter dependencies."""
        for obj in self.dependencies.values():
            yield obj["dep"]

    def update(self, dependency: Dependency) -> None:
        """Update dependency specifier."""
        if dependency.name in self.skip:
            return
        if dependency.name in self.dependencies:
            if dependency.version == "":
                return
            self.dependencies[dependency.name]["dep"] = dependency
            return
        self.extra[dependency.name] = dependency

    def check(self, dependency: Dependency) -> Tuple[Optional[str], int]:
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
        dependencies: OrderedDictType[str, Dependency],
        config: Dict[str, Dict],
        file: Path,
        main_dep_names: Optional[Set[str]] = None,
        string_dep_names: Optional[Set[str]] = None,
    ) -> None:
        """Initialize object."""
        self.dependencies = dependencies
        self.config = config
        self.file = file
        # When `main_dep_names` is provided, `__iter__` and `dump()` are
        # scoped to those entries. Group-only entries still live in
        # `self.dependencies` so `check()` lookups succeed (e.g. a
        # `pytest-asyncio` declared in `[tool.poetry.group.dev.dependencies]`
        # must satisfy a package-YAML dependency declaration), but they
        # don't get cross-compared against `tox.ini` or hoisted into
        # `[tool.poetry.dependencies]` by `--update` mode. The only caller
        # (`load`) passes a freshly-built set, so no defensive copy.
        self._main_dep_names = main_dep_names
        # Names of deps that originated from a plain-string spec (e.g.
        # `requests = "*"`). Only these are rewritten by `dump()`;
        # dict-form entries carry metadata (`optional`, `path`,
        # `develop`, `markers`) the `name = version` form can't represent.
        self._string_dep_names = string_dep_names

    def __iter__(self) -> Iterator[Dependency]:
        """Iterate dependencies as Dependency objects."""
        for name, dependency in self.dependencies.items():
            if dependency.name in self.ignore:
                continue
            if self._main_dep_names is not None and name not in self._main_dep_names:
                continue
            yield dependency

    def update(self, dependency: Dependency) -> None:
        """Update dependency specifier."""
        if dependency.name in self.ignore:
            return
        if dependency.name in self.dependencies and dependency.version == "":
            return
        self.dependencies[dependency.name] = dependency

    def check(self, dependency: Dependency) -> Tuple[Optional[str], int]:
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

    @staticmethod
    def _normalize_version(version: str) -> str:
        """Normalize a poetry version constraint to a pip-style specifier."""
        if version in ("", "*"):
            return ""
        if version.startswith("^"):
            # Deliberately lossy: PEP 440 has no caret, and the checker
            # compares specifiers as plain strings against package YAMLs
            # which use `==X.Y.Z`. Collapsing `^X.Y.Z` to `==X.Y.Z`
            # matches that convention; the upper bound (`<(X+1).0.0`)
            # implied by Poetry's caret semantics is dropped here.
            return version.replace("^", "==", 1)
        if version[0].isdigit():
            return f"=={version}"
        return version

    @classmethod
    def _dependency_from_spec(
        cls, name: str, spec: Any, pyproject_path: Path
    ) -> Optional[Dependency]:
        """Build a Dependency from a poetry dep spec (string or dict)."""
        if isinstance(spec, str):
            return Dependency(name=name, version=cls._normalize_version(spec))
        if isinstance(spec, dict):
            return Dependency(
                name=name,
                version=cls._normalize_version(spec.get("version", "")),
                extras=spec.get("extras"),
            )
        # Lists (multiple constraints with markers) and other shapes are
        # rare in our repos; surface them as a warning (with the file
        # path, for monorepo debuggability) so a future contributor
        # knows the entry was skipped rather than silently treated as
        # declared.
        logging.warning(
            "Skipping unrecognized dependency spec for %r in %s: "
            "expected str or dict, got %s.",
            name,
            pyproject_path,
            type(spec).__name__,
        )
        return None

    @classmethod
    def load(cls, pyproject_path: Path) -> Optional["PyProjectToml"]:
        """Load pyproject.toml dependencies.

        Reads `[tool.poetry.dependencies]` plus every
        `[tool.poetry.group.*.dependencies]` table. Dict-form entries are
        treated as declared even when they omit the `extras` key (so
        `optional = true` deps are visible), and dev/test-only entries
        no longer need to be duplicated into main deps to satisfy the
        check.

        Group-origin entries enter `self.dependencies` for `check()`
        lookups but are excluded from `__iter__` / `dump()` so that
        cross-validation against `tox.ini` and `--update` rewrites stay
        scoped to main runtime deps. See `__init__` for the rationale.

        :param pyproject_path: path to the pyproject.toml file.
        :return: a `PyProjectToml` instance, or `None` if the file has
            no `[tool.poetry.dependencies]` table (the `except KeyError`
            also triggers on a missing `[tool]` / `[tool.poetry]`
            parent).
        """
        with pyproject_path.open("rb") as fp:
            config = tomllib.load(fp)
        dependencies: OrderedDictType[str, Dependency] = OrderedDict()
        try:
            main_deps = config["tool"]["poetry"]["dependencies"]
        except KeyError:
            return None

        string_dep_names: Set[str] = set()

        def _ingest(table: Dict[str, Any]) -> None:
            for name, spec in table.items():
                if name in dependencies:
                    # Main is ingested first, so this branch only fires
                    # when a group entry collides with a main entry.
                    # Main wins (tighter version pins in dev groups are
                    # not the checker's concern); flag the silent drop.
                    logging.warning(
                        "Dependency %r appears in multiple tables in %s; "
                        "keeping the first occurrence (main wins).",
                        name,
                        pyproject_path,
                    )
                    continue
                dep = cls._dependency_from_spec(name, spec, pyproject_path)
                if dep is None:
                    continue
                dependencies[name] = dep
                if isinstance(spec, str):
                    string_dep_names.add(name)

        _ingest(main_deps)
        main_dep_names: Set[str] = set(dependencies)

        group_tables = config["tool"]["poetry"].get("group", {})
        if not isinstance(group_tables, dict):
            logging.warning(
                "[tool.poetry.group] in %s is not a table; ignoring.",
                pyproject_path,
            )
            group_tables = {}
        for group_name, group in group_tables.items():
            group_deps = group.get("dependencies") if isinstance(group, dict) else None
            if isinstance(group_deps, dict):
                _ingest(group_deps)
            else:
                logging.warning(
                    "[tool.poetry.group.%s.dependencies] in %s is not a "
                    "table or is missing; skipping group.",
                    group_name,
                    pyproject_path,
                )

        return cls(
            dependencies=dependencies,
            config=config,
            file=pyproject_path,
            main_dep_names=main_dep_names,
            string_dep_names=string_dep_names,
        )

    def dump(self) -> None:
        """Dump to file.

        Only updates the version of main deps that originated from a
        plain-string spec (e.g. ``requests = "*"``). Dict-form entries
        (``docker = { version = "==7.1.0", optional = true }``) carry
        metadata that the ``name = version`` form can't represent, so
        they're left untouched. Group-origin deps aren't in
        ``[tool.poetry.dependencies]`` and are never written there.
        """
        deps_table = self.config["tool"]["poetry"]["dependencies"]
        for name, dep in self.dependencies.items():
            if (
                self._string_dep_names is not None
                and name not in self._string_dep_names
            ):
                continue
            if name not in deps_table:
                continue
            deps_table[name] = dep.version if dep.version != "" else "*"
        with self.file.open("wb") as fp:
            tomli_w.dump(self.config, fp)


def load_packages_dependencies(packages_dir: Path) -> List:
    """Return a list of package dependencies."""
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
