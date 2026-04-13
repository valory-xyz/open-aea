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

"""Tests for fingerprinting packages."""

import random
import shutil
import tempfile
from pathlib import Path

import pytest
import yaml

from aea.configurations.base import PACKAGE_TYPE_TO_CONFIG_CLASS
from aea.configurations.constants import AEA_DIR
from aea.helpers.cid import CID
from aea.helpers.dependency_tree import COMPONENTS
from aea.helpers.fingerprint import (
    check_fingerprint,
    compute_fingerprint,
    update_fingerprint,
)

from tests.conftest import PACKAGES_DIR

CONFIG_CLASSES = {k.value: v for k, v in PACKAGE_TYPE_TO_CONFIG_CLASS.items()}
CONFIG_FILES = {k: Path(PACKAGES_DIR).rglob(f_name) for k, f_name in COMPONENTS}

# Framework-included packages shipped under `aea/` (scaffold templates, etc.)
# whose fingerprints are not tracked in `packages/packages.json` and therefore
# are not verified by `aea packages lock --check`. We verify them directly
# below so a source-vs-fingerprint drift gets caught by the test suite.
FRAMEWORK_PACKAGE_YAMLS = sorted(
    p for _, config_file in COMPONENTS for p in Path(AEA_DIR).rglob(config_file)
)


def test_compute_fingerprint():
    """Test compute_fingerprint"""

    ignore_pattern = "__init__.py"
    package_path = Path(PACKAGES_DIR)
    fingerprints = compute_fingerprint(package_path, fingerprint_ignore_patterns=None)
    assert all(map(lambda multihash: CID.is_cid(multihash), fingerprints.values()))

    n_fingerprints_without_ignore = len(fingerprints)
    n_init_dot_py = sum(p.endswith(ignore_pattern) for p in fingerprints)
    fingerprints = compute_fingerprint(package_path, (ignore_pattern,))
    assert len(fingerprints) + n_init_dot_py == n_fingerprints_without_ignore
    assert all(map(lambda multihash: CID.is_cid(multihash), fingerprints.values()))


@pytest.mark.parametrize("package_type, files", CONFIG_FILES.items())
def test_update_fingerprint(package_type, files):
    """Test update fingerprint"""

    def load_config(file_path):
        """Load config.yaml"""
        # we ignore overwrites below `---` in this test
        # tests dealing with loading are under `test_configurations`
        file_contents = file_path.read_text().split("---")
        base_doc = file_contents[0]
        json = yaml.safe_load(base_doc)
        return config_cls._create_or_update_from_json(json)

    def point_mutation(directory: Path) -> None:
        """Mutate random character in a random python file"""
        py_file = random.choice(list(directory.glob("*.py")))  # nosec
        content = Path(py_file).read_text()
        i = random.choice(range(len(content)))  # nosec
        new = content[:i] + chr(ord(content[i]) + 1) + content[i + 1 :]
        py_file.write_text(new)

    dir_none_error_msg = "configuration.directory cannot be None."
    config_cls = CONFIG_CLASSES.get(package_type)
    with tempfile.TemporaryDirectory() as tmp_dir:
        for file in files:
            # copy files and operate on those
            nested_dir = Path(tmp_dir, file.parent.parts[-1])
            shutil.copytree(file.parent, nested_dir)
            copied_file = nested_dir / file.name

            config = load_config(copied_file)
            with pytest.raises(ValueError, match=dir_none_error_msg):
                update_fingerprint(config)

            # no code accompanies the aea-config.yaml file
            # check agent returns True before directory check
            if package_type == "agent":
                assert check_fingerprint(config)
                shutil.rmtree(nested_dir)
                continue

            # check all other types of packages
            with pytest.raises(ValueError, match=dir_none_error_msg):
                check_fingerprint(config)
            config.directory = nested_dir

            assert check_fingerprint(config)
            original_fp = config.fingerprint
            point_mutation(nested_dir)
            assert not check_fingerprint(config)
            update_fingerprint(config)
            config = load_config(copied_file)
            config.directory = nested_dir
            assert check_fingerprint(config)
            assert not original_fp == config.fingerprint

            shutil.rmtree(nested_dir)

            # test fingerprint empty
            shutil.copy(file, tmp_dir)
            config = load_config(Path(tmp_dir) / file.name)
            assert config.fingerprint
            config.directory = Path(tmp_dir)
            update_fingerprint(config)
            config = load_config(Path(tmp_dir) / file.name)
            assert not config.fingerprint


@pytest.mark.parametrize(
    "yaml_path", FRAMEWORK_PACKAGE_YAMLS, ids=lambda p: str(p.relative_to(AEA_DIR))
)
def test_framework_package_fingerprints(yaml_path: Path) -> None:
    """Check that fingerprints of framework-included packages match their source.

    `aea packages lock --check` only verifies packages under `packages/`, not
    the scaffold and other framework-included packages shipped under `aea/`.
    This test closes that gap by running the same `check_fingerprint` logic
    directly on each yaml file. Any source change that isn't followed by
    `tox -e lock-packages` (which updates these fingerprints via
    `aea/cli/ipfs_hash.py`'s SCAFFOLD_PACKAGES extension) will fail here.
    """
    file_contents = yaml_path.read_text().split("---")
    base_doc = file_contents[0]
    json_data = yaml.safe_load(base_doc)
    package_type = json_data["type"]
    config_cls = CONFIG_CLASSES[package_type]
    config = config_cls._create_or_update_from_json(json_data)
    config.directory = yaml_path.parent
    assert check_fingerprint(config), (
        f"Fingerprint mismatch for {yaml_path.relative_to(AEA_DIR)}: "
        f"run `tox -e lock-packages` to regenerate."
    )
