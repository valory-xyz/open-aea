# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2026 Valory AG
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

"""Smoke tests for the aea-dev CLI.

These tests verify the CLI is wired correctly without exercising the
heavy command bodies. They protect against:

- Import errors at module load time (e.g. missing deps in setup.py)
- Commands silently disappearing from the registry on refactor
- ``--help`` failing because of an unhandled exception in click setup
"""

import pytest
from aea_dev_helpers.cli import cli
from click.testing import CliRunner

EXPECTED_COMMANDS = {
    "bump-version",
    "deploy-registry",
    "parse-lock-deps",
    "publish-local",
    "update-pkg-versions",
    "update-plugin-versions",
    "update-symlinks",
}


def test_cli_imports() -> None:
    """The cli module imports without raising."""
    import aea_dev_helpers.cli as mod  # noqa: F401  # pylint: disable=import-outside-toplevel


def test_cli_help_runs() -> None:
    """``aea-dev --help`` exits 0 and lists the command group."""
    runner = CliRunner()
    result = runner.invoke(cli, ["--help"])
    assert result.exit_code == 0, result.output
    assert "AEA development and release helper utilities" in result.output


def test_cli_all_commands_registered() -> None:
    """Every expected command is reachable from the cli group."""
    registered = set(cli.commands)
    missing = EXPECTED_COMMANDS - registered
    assert not missing, f"Missing commands: {sorted(missing)}"


@pytest.mark.parametrize("command", sorted(EXPECTED_COMMANDS))
def test_each_command_help_runs(command: str) -> None:
    """``aea-dev <cmd> --help`` exits 0 for every registered command.

    This catches subtle wiring bugs (e.g. a command body raising at
    import time, even before any options are parsed).

    :param command: the subcommand name to invoke ``--help`` against.
    """
    runner = CliRunner()
    result = runner.invoke(cli, [command, "--help"])
    assert result.exit_code == 0, result.output
