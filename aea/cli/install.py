# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2023 Valory AG
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
"""Implementation of the 'aea install' subcommand."""

from typing import Optional, Tuple, cast

import click

from aea.cli.utils.click_utils import PyPiDependency
from aea.cli.utils.context import Context
from aea.cli.utils.decorators import check_aea_project
from aea.cli.utils.loggers import logger
from aea.configurations.data_types import Dependency
from aea.exceptions import AEAException
from aea.helpers.install_dependency import call_pip, install_dependencies


@click.command()
@click.option(
    "-r",
    "--requirement",
    type=click.Path(exists=True, file_okay=True, dir_okay=False, readable=True),
    required=False,
    default=None,
    help="Install from the given requirements file.",
)
@click.option(
    "-e",
    "--extra-dependency",
    "extra_dependencies",
    type=PyPiDependency(),
    help="Provide extra dependency.",
    multiple=True,
)
@click.option(
    "--timeout",
    type=float,
    default=300.0,
    help="Specify timeout.",
)
@click.pass_context
@check_aea_project
def install(
    click_context: click.Context,
    requirement: Optional[str],
    extra_dependencies: Tuple[Dependency],
    timeout: float,
) -> None:
    """Install the dependencies of the agent."""
    ctx = cast(Context, click_context.obj)
    do_install(ctx, requirement, extra_dependencies, timeout=timeout)


def do_install(
    ctx: Context,
    requirement: Optional[str] = None,
    extra_dependencies: Optional[Tuple[Dependency]] = None,
    timeout: float = 300.0,
) -> None:
    """
    Install necessary dependencies.

    :param ctx: context object.
    :param requirement: optional str requirement.
    :param extra_dependencies: List of the extra dependencies to use
    :param timeout: timeout to wait pip to install

    :raises ClickException: if AEAException occurs.
    """
    try:
        if requirement:
            if extra_dependencies is not None and len(extra_dependencies) > 0:
                logger.debug(
                    "Extra dependencies will be ignored while installing from requirements file"
                )
            logger.debug("Installing the dependencies in '{}'...".format(requirement))
            _install_from_requirement(requirement, install_timeout=timeout)
        else:
            logger.debug("Installing all the dependencies...")
            dependencies = ctx.get_dependencies(extra_dependencies=extra_dependencies)
            install_dependencies(
                list(dependencies.values()),
                logger=logger,
                install_timeout=timeout,
            )
    except AEAException as e:
        raise click.ClickException(str(e))


def _install_from_requirement(file: str, install_timeout: float = 300) -> None:
    """
    Install from requirements.

    :param file: requirement.txt file path
    :param install_timeout: timeout to wait pip to install

    :raises AEAException: if an error occurs during installation.
    """
    try:
        call_pip(["install", "-r", file], timeout=install_timeout)
    except Exception:
        raise AEAException(
            "An error occurred while installing requirement file {}. Stopping...".format(
                file
            )
        )
