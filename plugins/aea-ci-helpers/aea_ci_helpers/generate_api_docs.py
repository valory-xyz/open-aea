#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2026 Valory AG
#   Copyright 2018-2019 Fetch.AI Limited
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

"""This tool generates the API docs."""

import argparse
import re
import shutil
import subprocess  # nosec
import sys
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

from aea.configurations.base import ComponentType, PublicId
from aea.configurations.constants import PACKAGES, SIGNING_PROTOCOL

DEFAULT_SOURCE_DIR = "aea"
DEFAULT_PACKAGES_DIR = PACKAGES
DEFAULT_PLUGINS_DIR = "plugins"
DEFAULT_DOCS_DIR = "docs"
DEFAULT_IGNORE_NAMES: Tuple[str, ...] = (
    r"^__init__\.py$",
    r"^__version__\.py$",
    r"^py\.typed$",
    r"^.*_pb2.py$",
)
# Plugins that should not have API docs generated (CI tooling, not framework API)
DEFAULT_IGNORE_PLUGINS: Tuple[str, ...] = ("aea-ci-helpers",)
DEFAULT_IGNORE_PREFIXES: Tuple[str, ...] = (
    str(Path("aea", "cli")),
    str(Path("aea", "connections", "scaffold")),
    str(Path("aea", "contracts", "scaffold")),
    str(Path("aea", "protocols", "scaffold")),
    str(Path("aea", "skills", "scaffold")),
    str(Path("aea", "decision_maker", "scaffold.py")),
    str(Path("aea", "error_handler", "scaffold.py")),
    str(Path("aea", "test_tools", "click_testing.py")),
)
DEFAULT_DEFAULT_PACKAGES: Tuple[Tuple[ComponentType, str], ...] = (
    (ComponentType.PROTOCOL, SIGNING_PROTOCOL),
)


@dataclass
class ApiDocsConfig:
    """Configuration for API docs generation.

    Parameters are declared explicitly so callers can customise the
    command for any repo (not just open-aea). All paths are resolved
    relative to the current working directory.
    """

    source_dir: Path = Path(DEFAULT_SOURCE_DIR)
    packages_dir: Path = Path(DEFAULT_PACKAGES_DIR)
    plugins_dir: Path = Path(DEFAULT_PLUGINS_DIR)
    docs_dir: Path = Path(DEFAULT_DOCS_DIR)
    default_packages: Tuple[Tuple[ComponentType, str], ...] = DEFAULT_DEFAULT_PACKAGES
    ignore_names: Tuple[str, ...] = DEFAULT_IGNORE_NAMES
    ignore_plugins: Tuple[str, ...] = DEFAULT_IGNORE_PLUGINS
    ignore_prefixes: Tuple[str, ...] = DEFAULT_IGNORE_PREFIXES
    parallel: bool = False

    @property
    def api_dir(self) -> Path:
        """Output directory for generated markdown files."""
        return self.docs_dir / "api"

    def should_skip(self, module_path: Path) -> bool:
        """Return true if the file should be skipped.

        :param module_path: the candidate file.
        :return: True if it should be excluded from API doc generation.
        """
        if any(re.search(pattern, module_path.name) for pattern in self.ignore_names):
            print(f"Skipping {module_path}: matches ignore pattern")
            return True
        if module_path.suffix != ".py":
            print(f"Skipping {module_path}: not a Python module")
            return True
        if any(
            is_relative_to(module_path, Path(prefix)) for prefix in self.ignore_prefixes
        ):
            print(f"Skipping {module_path}: ignored prefix")
            return True
        return False


def replace_underscores(text: str) -> str:
    """
    Replace escaped underscores in a text.

    :param text: the text to replace underscores in
    :return: the processed text
    """
    text_a = text.replace("\\_\\_", "`__`")
    text_b = text_a.replace("\\_", "`_`")
    return text_b


def is_relative_to(p1: Path, p2: Path) -> bool:
    """Check if a path is relative to another path."""
    return str(p1).startswith(str(p2))


def is_not_dir(p: Path) -> bool:
    """Call p.is_dir() method and negate the result."""
    return not p.is_dir()


def _dispatch(
    executor: Optional[ThreadPoolExecutor],
    dotted_path: str,
    doc_file: Path,
    futures: List[Future],
) -> None:
    """Run ``make_pydoc`` inline or submit it to the executor.

    In parallel mode the returned ``Future`` is appended to ``futures``
    so the caller can ``.result()`` on each job and surface any
    exception instead of silently dropping it.

    :param executor: optional thread pool; ``None`` runs inline.
    :param dotted_path: dotted module path to pass to pydoc-markdown.
    :param doc_file: destination markdown file.
    :param futures: accumulator for submitted jobs (parallel mode only).
    """
    if executor is None:
        make_pydoc(dotted_path, doc_file)
    else:
        futures.append(executor.submit(make_pydoc, dotted_path, doc_file))


def _generate_apidocs_source_modules(
    config: ApiDocsConfig,
    executor: Optional[ThreadPoolExecutor],
    futures: List[Future],
) -> None:
    """Generate API docs for the main source package.

    :param config: resolved configuration.
    :param executor: optional thread pool for parallel mode.
    :param futures: accumulator for submitted jobs.
    """
    for module_path in filter(is_not_dir, config.source_dir.rglob("*")):
        print(f"Processing {module_path}... ", end="")
        if config.should_skip(module_path):
            continue
        parents = module_path.parts[:-1]
        parents_without_root = module_path.parts[1:-1]
        last = module_path.stem
        doc_file = config.api_dir / Path(*parents_without_root) / f"{last}.md"
        dotted_path = ".".join(parents) + "." + last
        _dispatch(executor, dotted_path, doc_file, futures)


def _generate_apidocs_default_packages(
    config: ApiDocsConfig,
    executor: Optional[ThreadPoolExecutor],
    futures: List[Future],
) -> None:
    """Generate API docs for the configured default packages.

    :param config: resolved configuration.
    :param executor: optional thread pool for parallel mode.
    :param futures: accumulator for submitted jobs.
    """
    for component_type, default_package in config.default_packages:
        public_id = PublicId.from_str(default_package)
        author = public_id.author
        name = public_id.name
        type_plural = component_type.to_plural()
        package_dir = config.packages_dir / author / type_plural / name
        for module_path in package_dir.rglob("*.py"):
            print(f"Processing {module_path}...", end="")
            if config.should_skip(module_path):
                continue
            suffix = Path(str(module_path.relative_to(package_dir))[:-3] + ".md")
            dotted_path = ".".join(module_path.parts)[:-3]
            doc_file = config.api_dir / type_plural / name / suffix
            _dispatch(executor, dotted_path, doc_file, futures)


def _generate_apidocs_plugins(
    config: ApiDocsConfig,
    executor: Optional[ThreadPoolExecutor],
    futures: List[Future],
) -> None:
    """Generate API docs for plugins.

    :param config: resolved configuration.
    :param executor: optional thread pool for parallel mode.
    :param futures: accumulator for submitted jobs.
    """
    if not config.plugins_dir.is_dir():
        return
    for plugin in config.plugins_dir.iterdir():
        plugin_name = plugin.name
        if plugin_name in config.ignore_plugins:
            continue
        plugin_module_name = plugin_name.replace("-", "_")
        python_package_root = plugin / plugin_module_name
        if not python_package_root.is_dir():
            continue
        for module_path in python_package_root.rglob("*.py"):
            print(f"Processing {module_path}...", end="")
            if config.should_skip(module_path):
                continue
            relative_module_path = module_path.relative_to(python_package_root)
            suffix = Path(str(relative_module_path)[:-3] + ".md")
            dotted_path = ".".join(module_path.parts)[:-3]
            doc_file = config.api_dir / "plugins" / plugin_module_name / suffix
            _dispatch(executor, dotted_path, doc_file, futures)


def make_pydoc(dotted_path: str, dest_file: Path) -> None:
    """Make a PyDoc file."""
    print(
        f"Running with dotted path={dotted_path} and dest_file={dest_file}... ", end=""
    )
    try:
        api_doc_content = run_pydoc_markdown(dotted_path)
        dest_file.parent.mkdir(parents=True, exist_ok=True)
        dest_file.write_text(api_doc_content)
    except Exception as e:  # pylint: disable=broad-except
        print(f"Error: {str(e)}")
        return
    print("Done!")


def run_pydoc_markdown(module: str) -> str:
    """
    Run pydoc-markdown.

    :param module: the dotted path.
    :return: the PyDoc content (pre-processed).
    """
    pydoc = subprocess.Popen(  # nosec  # pylint: disable=consider-using-with
        ["pydoc-markdown", "-m", module, "-I", "."],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    stdout, _ = pydoc.communicate()
    pydoc.wait()
    stdout_text = stdout.decode("utf-8")
    text = replace_underscores(stdout_text)
    return text


def generate_api_docs(config: Optional[ApiDocsConfig] = None) -> None:
    """Generate the api docs.

    :param config: optional ``ApiDocsConfig`` controlling paths and
        ignore rules. Defaults to open-aea layout when omitted.
    """
    cfg = config if config is not None else ApiDocsConfig()
    shutil.rmtree(cfg.api_dir, ignore_errors=True)
    cfg.api_dir.mkdir(parents=True)
    executor: Optional[ThreadPoolExecutor] = None
    futures: List[Future] = []
    if cfg.parallel:
        executor = ThreadPoolExecutor()
    try:
        _generate_apidocs_default_packages(cfg, executor, futures)
        _generate_apidocs_source_modules(cfg, executor, futures)
        _generate_apidocs_plugins(cfg, executor, futures)
        # Re-raise any exception swallowed by a background worker so
        # parallel mode has the same failure semantics as serial mode.
        for fut in futures:
            fut.result()
    finally:
        if executor is not None:
            executor.shutdown(wait=True)


def install(package: str) -> int:
    """
    Install a PyPI package by calling pip.

    :param package: the package name and version specifier.
    :return: the return code.
    """
    return subprocess.check_call(  # nosec
        [sys.executable, "-m", "pip", "install", package]
    )


if __name__ == "__main__":
    from aea.helpers.git import check_working_tree_is_dirty

    parser = argparse.ArgumentParser("generate_api_docs")
    parser.add_argument(
        "--check-clean", action="store_true", help="Check if the working tree is clean."
    )
    arguments = parser.parse_args()

    res = shutil.which("pydoc-markdown")
    if res is None:
        install("pydoc-markdown==3.3.0")
        sys.exit(1)

    generate_api_docs()

    if arguments.check_clean:
        is_clean = check_working_tree_is_dirty()
        if not is_clean:
            sys.exit(1)
