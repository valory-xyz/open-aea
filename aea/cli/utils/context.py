# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2024 Valory AG
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
"""A module with context tools of the aea cli."""
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, cast

from aea.cli.registry.settings import REGISTRY_LOCAL, REGISTRY_TYPES
from aea.cli.utils.loggers import logger
from aea.configurations.base import (
    AgentConfig,
    Dependencies,
    Dependency,
    PackageType,
    PublicId,
    _get_default_configuration_file_name_from_type,
)
from aea.configurations.constants import (
    DEFAULT_AEA_CONFIG_FILE,
    DEFAULT_REGISTRY_NAME,
    VENDOR,
)
from aea.configurations.loader import ConfigLoader
from aea.configurations.pypi import (
    is_satisfiable,
    is_simple_dep,
    merge_dependencies_list,
    to_set_specifier,
)
from aea.exceptions import AEAException
from aea.helpers.io import open_file


class Context:
    """A class to keep configuration of the cli tool."""

    agent_config: AgentConfig

    _registry_type: Optional[str]

    def __init__(self, cwd: str, verbosity: str, registry_path: Optional[str]) -> None:
        """Init the context."""
        self.config = dict()  # type: Dict
        self.cwd = cwd
        self.verbosity = verbosity
        self.clean_paths: List = []
        self._registry_path = registry_path
        self._registry_type = None

    @property
    def registry_type(
        self,
    ) -> str:
        """Returns registry type to be used for session"""
        if self._registry_type is None:
            logger.warning("Registry not set, returning local as registry type")
            return REGISTRY_LOCAL

        return self._registry_type

    @registry_type.setter
    def registry_type(self, value: str) -> None:
        """Set registry value."""
        if value is not None:
            if value not in REGISTRY_TYPES:
                raise ValueError(
                    f"{value} not allowed as registry type; Allowed registry types: {REGISTRY_TYPES}"
                )

            self._registry_type = value

    @property
    def registry_path(self) -> str:
        """Get registry path specified or from config or default one with check is it present."""
        # registry path is provided or in config or default
        if self._registry_path:
            registry_path = Path(self._registry_path)
            if not (registry_path.exists() and registry_path.is_dir()):
                raise ValueError(
                    f"Registry path directory provided ({self._registry_path}) can not be found. Current work dir is {self.cwd}"
                )
            return str(registry_path)

        registry_path = (Path(self.cwd) / DEFAULT_REGISTRY_NAME).absolute()
        if registry_path.is_dir():
            return str(registry_path)
        registry_path = (Path(self.cwd) / ".." / DEFAULT_REGISTRY_NAME).absolute()
        if registry_path.is_dir():
            return str(registry_path)
        raise ValueError(
            f"Registry path not provided and local registry `{DEFAULT_REGISTRY_NAME}` not found in current ({self.cwd}) and parent directory."
        )

    @property
    def skip_aea_validation(self) -> bool:
        """
        Get the 'skip_aea_validation' flag.

        If true, validation of the AEA version for loaded configuration
        file is skipped.

        :return: the 'skip_aea_validation'
        """
        return self.config.get("skip_aea_validation", True)

    @property
    def agent_loader(self) -> ConfigLoader:
        """Get the agent loader."""
        return ConfigLoader.from_configuration_type(
            PackageType.AGENT, skip_aea_validation=self.skip_aea_validation
        )

    @property
    def protocol_loader(self) -> ConfigLoader:
        """Get the protocol loader."""
        return ConfigLoader.from_configuration_type(
            PackageType.PROTOCOL, skip_aea_validation=self.skip_aea_validation
        )

    @property
    def connection_loader(self) -> ConfigLoader:
        """Get the connection loader."""
        return ConfigLoader.from_configuration_type(
            PackageType.CONNECTION, skip_aea_validation=self.skip_aea_validation
        )

    @property
    def skill_loader(self) -> ConfigLoader:
        """Get the skill loader."""
        return ConfigLoader.from_configuration_type(
            PackageType.SKILL, skip_aea_validation=self.skip_aea_validation
        )

    @property
    def contract_loader(self) -> ConfigLoader:
        """Get the contract loader."""
        return ConfigLoader.from_configuration_type(
            PackageType.CONTRACT, skip_aea_validation=self.skip_aea_validation
        )

    @property
    def custom_loader(self) -> ConfigLoader:
        """Get the custom loader."""
        return ConfigLoader.from_configuration_type(
            PackageType.CUSTOM, skip_aea_validation=self.skip_aea_validation
        )

    def set_config(self, key: str, value: Any) -> None:
        """
        Set a config.

        :param key: the key for the configuration.
        :param value: the value associated with the key.
        """
        self.config[key] = value
        logger.debug("  config[{}] = {}".format(key, value))

    @staticmethod
    def _get_item_dependencies(item_type: str, public_id: PublicId) -> Dependencies:
        """Get the dependencies from item type and public id."""
        item_type_plural = item_type + "s"
        default_config_file_name = _get_default_configuration_file_name_from_type(
            item_type
        )
        path = Path(
            VENDOR,
            public_id.author,
            item_type_plural,
            public_id.name,
            default_config_file_name,
        )
        if not path.exists():
            path = Path(item_type_plural, public_id.name, default_config_file_name)
        config_loader = ConfigLoader.from_configuration_type(item_type)
        with open_file(path) as fp:
            config = config_loader.load(fp)
        deps = cast(Dependencies, config.dependencies)
        return deps

    @staticmethod
    def _find_unsatisfiable_dependencies(dependencies: Dependencies) -> Dependencies:
        """
        Find unsatisfiable dependencies.

        It only checks among 'simple' dependencies (i.e. if it has no field specified,
        or only the 'version' field set.)

        :param dependencies: the dependencies to check.
        :return: the unsatisfiable dependencies.
        """
        return {
            name: dep
            for name, dep in dependencies.items()
            if is_simple_dep(dep) and not is_satisfiable(to_set_specifier(dep))
        }

    def _get_dependencies_by_item_type(self, item_type: PackageType) -> Dependencies:
        """Get the dependencies from item type and public id."""
        if item_type == PackageType.AGENT:
            return self.agent_config.dependencies
        dependency_to_package: Dict[str, List[Tuple[PublicId, Dependency]]] = {}
        dependencies = []
        for item_id in getattr(self.agent_config, item_type.to_plural()):
            package_dependencies = self._get_item_dependencies(item_type.value, item_id)
            dependencies += [package_dependencies]
            for dep, spec in package_dependencies.items():
                if dep not in dependency_to_package:
                    dependency_to_package[dep] = []
                dependency_to_package[dep].append((item_id, spec))

        merged_dependencies = merge_dependencies_list(*dependencies)
        unsat_dependencies = self._find_unsatisfiable_dependencies(merged_dependencies)
        if len(unsat_dependencies) > 0:
            error = f"Error while merging dependencies for {item_type.to_plural()}"
            error += "; Joint version specifier is unsatisfiable for following dependencies:\n"
            error += "======================================\n"
            for name, spec in unsat_dependencies.items():
                error += f"Dependency: {name}\n"
                error += f"Specifier: {to_set_specifier(spec)}\n"
                error += "Packages containing dependency: \n"
                for package, dep_spec in dependency_to_package[name]:
                    error += f"  - {package.without_hash()}: {dep_spec.get_pip_install_args()[0]}\n"
                error += "======================================\n"

            raise AEAException(error[:-1])
        return merged_dependencies

    def get_dependencies(
        self,
        extra_dependencies: Optional[Tuple[Dependency]] = None,
    ) -> Dependencies:
        """
        Aggregate the dependencies from every component.

        :param extra_dependencies: List of the extra dependencies to use, if the
                                extra dependencies and agent dependencies have conflicts
                                the packages from extra dependencies list will be prefered
                                over the agent dependencies
        :return: a list of dependency version specification. e.g. ["gym >= 1.0.0"]
        """
        dependencies: Dependencies = {}

        def _update_dependencies(updates: Dependencies) -> None:
            """Update dependencies."""
            for dep, spec in updates.items():
                if dep in dependencies and dependencies[dep] != spec:
                    logger.debug(
                        f"`{dependencies[dep].get_pip_install_args()}` "
                        f"will be overridden by {spec.get_pip_install_args()}"
                    )
                dependencies[dep] = spec

        for item_type in (
            PackageType.PROTOCOL,
            PackageType.CONTRACT,
            PackageType.CUSTOM,
            PackageType.CONNECTION,
            PackageType.SKILL,
            PackageType.AGENT,
        ):
            logger.debug(f"Loading {item_type.value} dependencies")
            type_deps = self._get_dependencies_by_item_type(item_type)
            _update_dependencies(type_deps)

        if extra_dependencies is not None and len(extra_dependencies) > 0:
            logger.debug("Loading extra dependencies")
            type_deps = {spec.name: spec for spec in extra_dependencies}
            _update_dependencies(type_deps)

        return dependencies

    def dump_agent_config(self) -> None:
        """Dump the current agent configuration."""
        with open(os.path.join(self.cwd, DEFAULT_AEA_CONFIG_FILE), "w") as f:
            self.agent_loader.dump(self.agent_config, f)
