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
# pylint: disable=cyclic-import

"""Update symlinks for the project, cross-platform compatible."""

import contextlib
import os
import sys
import traceback
from functools import reduce
from pathlib import Path
from typing import Generator, List, Optional, Tuple, Union


def _get_symlinks(root_path: Path) -> List[Tuple[Path, Path]]:
    """
    Build the list of (link_path, target_path) pairs relative to the given root.

    :param root_path: the repository root path.
    :return: list of (link_path, target_path) tuples.
    """
    test_data = root_path / "tests" / "data"
    test_dummy_aea_dir = test_data / "dummy_aea"
    fetchai_packages = root_path / "packages" / "fetchai"
    open_aea_packages = root_path / "packages" / "open_aea"

    symlinks: List[Tuple[Path, Path]] = [
        (test_dummy_aea_dir / "skills" / "dummy", test_data / "dummy_skill"),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "protocols" / "default",
            fetchai_packages / "protocols" / "default",
        ),
        (
            test_dummy_aea_dir / "vendor" / "open_aea" / "protocols" / "signing",
            open_aea_packages / "protocols" / "signing",
        ),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "protocols" / "state_update",
            fetchai_packages / "protocols" / "state_update",
        ),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "protocols" / "fipa",
            fetchai_packages / "protocols" / "fipa",
        ),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "protocols" / "oef_search",
            fetchai_packages / "protocols" / "oef_search",
        ),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "connections" / "local",
            fetchai_packages / "connections" / "local",
        ),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "contracts" / "erc1155",
            fetchai_packages / "contracts" / "erc1155",
        ),
        (
            test_dummy_aea_dir / "vendor" / "fetchai" / "skills" / "error",
            fetchai_packages / "skills" / "error",
        ),
    ]
    return symlinks


def make_symlink(link_name: str, target: str) -> None:
    """
    Make a symbolic link, cross platform.

    :param link_name: the link name.
    :param target: the target.
    """
    try:
        Path(link_name).unlink()
    except FileNotFoundError:
        pass
    Path(link_name).symlink_to(target, target_is_directory=True)


@contextlib.contextmanager
def cd(path: Union[Path, str]) -> Generator:
    """Change directory with context manager."""
    old_cwd = os.getcwd()
    try:
        os.chdir(path)
        yield
        os.chdir(old_cwd)
    except Exception as e:  # pylint: disable=broad-except
        os.chdir(old_cwd)
        raise e from e


def create_symlink(link_path: Path, target_path: Path, root_path: Path) -> int:
    """
    Change directory and call the cross-platform script.

    The working directory must be the parent of the symbolic link name
    when executing 'create_symlink_crossplatform.sh'. Hence, we
    need to translate target_path into the relative path from the
    symbolic link directory to the target directory.

    So:
    1) from link_path, extract the number of jumps to the parent directory
      in order to reach the repository root directory, and chain many "../" paths.
    2) from target_path, compute the relative path to the root
    3) relative_target_path is just the concatenation of the results from step (1) and (2).

    For instance, given
    - link_path: './directory_1//symbolic_link
    - target_path: './directory_2/target_path

    we want to compute:
    - link_path: 'symbolic_link' (just the last bit)
    - relative_target_path: '../../directory_1/target_path'

    The resulting command on UNIX systems will be:

        cd directory_1 && ln -s ../../directory_1/target_path symbolic_link

    :param link_path: the link path
    :param target_path: the target path
    :param root_path: the root path
    :return: exit code
    """
    working_directory = link_path.parent
    target_relative_to_root = target_path.relative_to(root_path)
    cwd_relative_to_root = working_directory.relative_to(root_path)
    nb_parents = len(cwd_relative_to_root.parents)
    root_relative_to_cwd = reduce(
        lambda x, y: x / y, [Path("../")] * nb_parents, Path(".")
    )
    link_name = link_path.name
    target = root_relative_to_cwd / target_relative_to_root
    with cd(working_directory.absolute()):
        make_symlink(str(link_name), str(target))
    return 0


def update_symlinks(root_path: Optional[Path] = None) -> None:
    """
    Update all symlinks in the project.

    :param root_path: the repository root path. If None, auto-detect.
    """
    if root_path is None:
        # Try to find the repository root by looking for a known marker
        candidate = Path.cwd()
        while candidate != candidate.parent:
            if (candidate / "packages").is_dir() and (candidate / "tests").is_dir():
                root_path = candidate
                break
            candidate = candidate.parent
        if root_path is None:
            root_path = Path.cwd()

    symlinks = _get_symlinks(root_path)
    failed = False
    for link_name, target in symlinks:
        print("Linking {} to {}".format(link_name, target))
        try:
            link_name.unlink()
        except FileNotFoundError:
            pass
        try:
            return_code = create_symlink(link_name, target, root_path)
        except Exception as e:  # pylint: disable=broad-except
            exception = e
            return_code = 1
            traceback.print_exc()
            print(
                "Last command failed with return code {} and exception {}".format(
                    return_code, exception
                )
            )
            failed = True

    if failed:
        sys.exit(1)
