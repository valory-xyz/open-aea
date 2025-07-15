# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2025 Valory AG
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

"""Package manager V1"""

import copy
import json
import logging
import traceback
from collections import OrderedDict
from enum import Enum
from itertools import chain
from pathlib import Path
from typing import Callable, Dict, List, Optional
from typing import OrderedDict as OrderedDictType
from typing import Union, cast

from requests import get as r_get

from aea.configurations.constants import PACKAGES
from aea.configurations.data_types import PackageId, PackageType
from aea.helpers.fingerprint import check_fingerprint
from aea.helpers.ipfs.base import IPFSHashOnly
from aea.package_manager.base import (
    BasePackageManager,
    ConfigLoaderCallableType,
    PACKAGES_FILE,
    PACKAGE_SOURCE_RE,
    PackageFileNotValid,
    PackageIdToHashMapping,
    PackageNotValid,
    PackagesSourceNotValid,
    load_configuration,
)


GIT_TAGS_URL = "https://api.github.com/repos/{repo}/tags"
PACKAGE_FILE_REMOTE_URL = (
    "https://raw.githubusercontent.com/{repo}/{tag}/packages/packages.json"
)

_PACKAGE_ORDER = [
    PackageType.CUSTOM,
    PackageType.PROTOCOL,
    PackageType.CONTRACT,
    PackageType.CONNECTION,
    PackageType.SKILL,
    PackageType.AGENT,
    PackageType.SERVICE,
]


class PackageManagerV1(BasePackageManager):
    """Package manager V1"""

    _third_party_packages: PackageIdToHashMapping
    _dev_packages: PackageIdToHashMapping

    class LocalPackageType(Enum):
        """Local package types."""

        DEV = "dev"
        THIRD_PARTY = "third_party"

    def __init__(  # pylint: disable=too-many-positional-arguments
        self,
        path: Path,
        dev_packages: Optional[PackageIdToHashMapping] = None,
        third_party_packages: Optional[PackageIdToHashMapping] = None,
        config_loader: ConfigLoaderCallableType = load_configuration,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Initialize object."""
        super().__init__(
            path=path,
            config_loader=config_loader,
            logger=logger,
        )

        self._dev_packages = dev_packages or OrderedDict()
        self._third_party_packages = third_party_packages or OrderedDict()

    @property
    def dev_packages(
        self,
    ) -> PackageIdToHashMapping:
        """Returns mappings of package ids -> package hash"""

        return self._dev_packages

    @property
    def third_party_packages(
        self,
    ) -> PackageIdToHashMapping:
        """Returns mappings of package ids -> package hash"""

        return self._third_party_packages

    @property
    def all_packages(self) -> PackageIdToHashMapping:
        """Return all packages."""
        return OrderedDict(
            chain(self.dev_packages.items(), self.third_party_packages.items())
        )

    def get_package_hash(self, package_id: PackageId) -> Optional[str]:
        """Get package hash."""
        package_id = package_id.without_hash()
        return self.dev_packages.get(
            package_id, self.third_party_packages.get(package_id)
        )

    def is_third_party_package(self, package_id: PackageId) -> bool:
        """Check if a package is third party package."""

        return self._third_party_packages.get(package_id) is not None

    def is_dev_package(self, package_id: PackageId) -> bool:
        """Check if a package is third party package."""

        return self._dev_packages.get(package_id) is not None

    def add_package(
        self,
        package_id: PackageId,
        with_dependencies: bool = False,
        allow_update: bool = False,
    ) -> "PackageManagerV1":
        """Add package."""
        super().add_package(
            package_id=package_id,
            with_dependencies=with_dependencies,
            allow_update=allow_update,
        )
        self._third_party_packages[package_id] = self.calculate_hash_from_package_id(
            package_id
        )
        return self

    @staticmethod
    def _get_latest_tag(repo: str) -> str:
        """Get latest tag for the repository."""

        response = r_get(GIT_TAGS_URL.format(repo=repo), timeout=30)
        if response.status_code != 200:
            raise PackagesSourceNotValid(
                f"Fetching tags from `{repo}` failed with message '"
                + response.json()["message"]
                + "'"
            )

        latest_tag_data, *_ = response.json()
        return latest_tag_data["name"]

    @staticmethod
    def _get_packages_json(repo: str, tag: str) -> Dict[str, Dict[str, str]]:
        """Get `packages.json`."""

        response = r_get(PACKAGE_FILE_REMOTE_URL.format(repo=repo, tag=tag), timeout=30)
        if response.status_code != 200:
            raise PackagesSourceNotValid(
                f"Fetching packages from `{repo}` failed with message '"
                + response.text
                + "'"
            )
        return response.json()

    def _update_hashes_from_sources(self, sources: List[str]) -> None:
        """Update hashes from sources"""

        _updated_third_party_packages = copy.deepcopy(self.third_party_packages)

        self._logger.info("Fetching hashes from sources")
        for source in sources:
            source_regex = PACKAGE_SOURCE_RE.match(source)
            if source_regex is None:
                raise PackagesSourceNotValid(
                    f"Provided source name is not valid `{source}`"
                )

            repo, _, _, tag = source_regex.groups()
            if tag is None:
                tag = self._get_latest_tag(repo=repo)

            packages = self._get_packages_json(repo=repo, tag=tag)
            package_manager = self.from_json(packages=packages)

            for package_id in _updated_third_party_packages:
                latest_hash = package_manager.dev_packages.get(package_id)
                if latest_hash is None:
                    continue

                self._logger.info(
                    f"Found hash for third party package {package_id} in source `{repo}`, updating hash"
                )
                _updated_third_party_packages[package_id] = latest_hash

        self._third_party_packages = _updated_third_party_packages
        self.dump(file=self._packages_file)

    def register(
        self,
        package_path: Path,
        package_type: Optional[PackageType] = None,
    ) -> "PackageManagerV1":
        """Add package to the index."""
        package_type = package_type or PackageType(package_path.parent.name[:-1])
        package_config = self.config_loader(package_type, package_path)
        self.update_fingerprints(package_id=package_config.package_id)
        self._dev_packages[package_config.package_id] = IPFSHashOnly.hash_directory(
            dir_path=str(package_path)
        )
        return self

    def sync(  # pylint: disable=too-many-positional-arguments
        self,
        dev: bool = False,
        third_party: bool = True,
        update_packages: bool = False,
        update_hashes: bool = False,
        sources: Optional[List[str]] = None,
    ) -> "PackageManagerV1":
        """Sync local packages to the remote registry."""

        if update_packages and update_hashes:
            raise ValueError(
                "Both `update_packages` and `update_hashes` cannot be set to `True`."
            )
        self._logger.info(f"Performing sync @ {self.path}")

        if sources is not None and len(sources) > 0:
            self._update_hashes_from_sources(sources=sources)

        sync_needed = False
        if third_party:
            self._logger.info("Checking third party packages.")
            (
                _sync_needed,
                hash_updates_third_party,
                package_updates_third_party,
            ) = self._sync(
                packages=self.third_party_packages,
                update_hashes=update_hashes,
                update_packages=update_packages,
            )

            sync_needed = sync_needed or _sync_needed
            if update_hashes and hash_updates_third_party:
                third_party_package_id = "\n\t- ".join(
                    map(str, hash_updates_third_party)
                )
                self._logger.warning(
                    f"Hashes for follwing third party module has changed.\n\t- {third_party_package_id}"
                )

            if update_packages and package_updates_third_party:
                self._logger.info("Updating third party packages.")
                for package_id, _ in package_updates_third_party.items():
                    self._logger.info(f"Updating {package_id}")
                    self.update_package(package_id=package_id)

        if dev:
            self._logger.info("Checking dev packages.")
            _sync_needed, hash_updates_dev, package_updates_dev = self._sync(
                packages=self.dev_packages,
                update_hashes=update_hashes,
                update_packages=update_packages,
            )
            sync_needed = sync_needed or _sync_needed

            if update_hashes:
                self._dev_packages = hash_updates_dev

            if update_packages and package_updates_dev:
                self._logger.info("Updating dev packages.")
                for package_id, _ in package_updates_dev.items():
                    self._logger.info(f"Updating {package_id}")
                    self.update_package(package_id=package_id)

        if update_hashes:
            self._logger.info("Updating hashes")
            self.dump()

        if sync_needed:
            self._logger.info("Sync complete")
            self._logger.info("Updating hashes")
            self.dump()
        else:
            self._logger.info("No package was updated.")

        return self

    def update_package_hashes(
        self,
        selector_prompt: Optional[Callable[[], str]] = None,
        skip_missing: bool = False,
    ) -> "PackageManagerV1":
        """Update package.json file."""

        for package_id in self.iter_dependency_tree():
            self.update_fingerprints(package_id=package_id)
            self.update_dependencies(package_id=package_id)

            package_hash = self.calculate_hash_from_package_id(package_id=package_id)
            is_dev_package = self.is_dev_package(package_id=package_id)
            is_third_party_package = self.is_third_party_package(package_id=package_id)

            if is_dev_package:
                if self._dev_packages[package_id] == package_hash:
                    continue

                self._logger.info(f"Updating hash for {package_id}")
                self._dev_packages[package_id] = package_hash
                continue

            if is_third_party_package:
                if self._third_party_packages[package_id] == package_hash:
                    continue

                self._third_party_packages[package_id] = package_hash
                self._logger.warning(
                    "Hash change detected for third party package"
                    f"\n\tPackage: {package_id}"
                    f"\n\tCalculated hash: {package_hash}"
                    f"\n\tExpected hash: {self._third_party_packages[package_id]}"
                )
                continue

            if skip_missing:
                continue

            if selector_prompt is None:
                raise PackageNotValid(
                    f"Found a package which is not listed in the `packages.json` with package id {package_id}"
                )

            self._logger.info(f"A new package found with package ID {package_id}")
            package_type = self.LocalPackageType(selector_prompt())
            if package_type == self.LocalPackageType.DEV:
                self._logger.info("Adding package to dev packages")
                self._dev_packages[package_id] = package_hash
            else:
                self._logger.info("Adding package to third party packages")
                self._third_party_packages[package_id] = package_hash

        return self

    @staticmethod
    def _calculate_hash(package_path: Union[Path, str]) -> str:
        """Calculate hash for path."""
        return IPFSHashOnly.get(str(package_path))

    def verify(
        self,
    ) -> int:
        """Verify fingerprints and outer hash of all available packages."""

        failed = False
        try:
            for package_id in self.iter_dependency_tree():
                self._logger.info(f"Verifying {package_id}")
                package_path = self.package_path_from_package_id(package_id)
                configuration_obj = self._get_package_configuration(
                    package_id=package_id
                )

                calculated_hash = self._calculate_hash(str(package_path))
                fingerprint_check = check_fingerprint(configuration_obj)

                if not fingerprint_check:
                    failed = True
                    self._logger.error(
                        f"Fingerprints does not match for {package_id} @ {package_path}"
                    )
                    if self.is_third_party_package(package_id=package_id):
                        self._third_party_packages[package_id] = calculated_hash
                    continue

                expected_hash = self.dev_packages.get(
                    package_id, self.third_party_packages.get(package_id)
                )
                if expected_hash is None:
                    failed = True
                    self._logger.error(f"Cannot find hash for {package_id}")
                    continue
                if calculated_hash != expected_hash:
                    # this update is required for further dependency checks for
                    # packages where this package is a dependency
                    if self.is_third_party_package(package_id=package_id):
                        self._third_party_packages[package_id] = calculated_hash
                    if self.is_dev_package(package_id=package_id):
                        self._dev_packages[package_id] = calculated_hash
                    self._logger.error(f"Hash does not match for {package_id}")
                    self._logger.error(f"\tCalculated hash: {calculated_hash}")
                    self._logger.error(f"\tExpected hash: {expected_hash}")
                    failed = True
                    continue

                if not self.is_dependencies_hashes_match(package_id, configuration_obj):
                    failed = True

        except Exception:  # pylint: disable=broad-except
            traceback.print_exc()
            failed = True

        return int(failed)

    @property
    def json(
        self,
    ) -> OrderedDictType:
        """Json representation"""

        data: OrderedDictType[str, OrderedDictType[str, str]] = OrderedDict()
        data["dev"] = OrderedDict()
        data["third_party"] = OrderedDict()

        for package_id, package_hash in sorted(
            self._dev_packages.items(),
            key=lambda x: _PACKAGE_ORDER.index(x[0].package_type),
        ):
            data["dev"][package_id.to_uri_path] = package_hash

        for package_id, package_hash in sorted(
            self._third_party_packages.items(),
            key=lambda x: _PACKAGE_ORDER.index(x[0].package_type),
        ):
            data["third_party"][package_id.to_uri_path] = package_hash

        return data

    @staticmethod
    def _load_packages(packages_file: Path) -> Dict[str, Dict[str, str]]:
        """Load packages json file."""
        return cast(Dict, json.loads(packages_file.read_text()))

    @classmethod
    def from_json(
        cls,
        packages: Dict[str, Dict[str, str]],
        packages_dir: Optional[Path] = None,
        config_loader: ConfigLoaderCallableType = load_configuration,
    ) -> "PackageManagerV1":
        """Initialize from json object"""

        if "dev" not in packages:
            raise PackageFileNotValid(
                "`packages.json` file not valid, no development packages found"
            )

        if "third_party" not in packages:
            raise PackageFileNotValid(
                "`packages.json` file not valid, no third party packages found"
            )

        dev_packages = OrderedDict()
        for package_id, package_hash in packages["dev"].items():
            dev_packages[PackageId.from_uri_path(package_id)] = package_hash

        third_party_packages = OrderedDict()
        for package_id, package_hash in packages["third_party"].items():
            third_party_packages[PackageId.from_uri_path(package_id)] = package_hash

        return cls(
            path=(packages_dir or Path.cwd() / PACKAGES),
            dev_packages=dev_packages,
            third_party_packages=third_party_packages,
            config_loader=config_loader,
        )

    @classmethod
    def from_dir(
        cls,
        packages_dir: Path,
        config_loader: ConfigLoaderCallableType = load_configuration,
    ) -> "PackageManagerV1":
        """Initialize from packages directory."""
        packages_file = packages_dir / PACKAGES_FILE
        packages = cls._load_packages(packages_file)
        return cls.from_json(
            packages=packages,
            packages_dir=packages_dir,
            config_loader=config_loader,
        )
