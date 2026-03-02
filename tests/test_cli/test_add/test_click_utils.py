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

"""Module with tests for click utils of the aea cli."""

import click
import pytest
from click import ClickException
from click.testing import CliRunner

from aea.cli.registry.settings import (
    REGISTRY_LOCAL,
    REGISTRY_MIXED,
    REGISTRY_REMOTE,
    REMOTE_HTTP,
    REMOTE_IPFS,
)
from aea.cli.utils.click_utils import (
    registry_flag,
    remote_registry_flag,
    reraise_as_click_exception,
)


def test_reraise_as_click_exception() -> None:
    """Test reraise_as_click_exception"""

    # all are exceptions
    assert issubclass(ValueError, Exception)
    assert issubclass(ZeroDivisionError, Exception)
    assert issubclass(ClickException, Exception)

    # none are subclasses of one-another
    assert not issubclass(ValueError, ClickException)
    assert not issubclass(ClickException, ValueError)

    assert not issubclass(ValueError, ZeroDivisionError)
    assert not issubclass(ZeroDivisionError, ValueError)

    # Beware! Does not fail because we exit early
    with pytest.raises(ValueError):
        with pytest.raises(ZeroDivisionError):
            raise ValueError()
        raise AssertionError()

    # 1. do not raise on pass
    with reraise_as_click_exception():
        pass

    with reraise_as_click_exception(Exception):
        pass

    # 2. raise ClickException instead of ValueError
    with pytest.raises(ClickException):
        with reraise_as_click_exception(ValueError):
            raise ValueError()

    # 3. do not raise on another Exception
    with pytest.raises(ZeroDivisionError):
        with reraise_as_click_exception(ValueError):
            raise ZeroDivisionError()


class TestRegistryFlag:
    """Tests for registry_flag decorator with different defaults."""

    @staticmethod
    def _make_command(default_registry: str) -> click.Command:
        """Create a click command decorated with registry_flag."""

        @click.command()
        @registry_flag(default_registry=default_registry)
        def cmd(registry: str) -> None:
            click.echo(registry)

        return cmd

    @pytest.mark.parametrize(
        "default_registry",
        [REGISTRY_LOCAL, REGISTRY_REMOTE, REGISTRY_MIXED],
    )
    def test_no_flag_uses_configured_default(self, default_registry: str) -> None:
        """Test that omitting flags yields the configured default."""
        cmd = self._make_command(default_registry)
        result = CliRunner().invoke(cmd, [])
        assert result.exit_code == 0
        assert result.output.strip() == default_registry

    @pytest.mark.parametrize(
        "default_registry",
        [REGISTRY_LOCAL, REGISTRY_REMOTE, REGISTRY_MIXED],
    )
    @pytest.mark.parametrize(
        "flag,expected",
        [
            ("--local", REGISTRY_LOCAL),
            ("--remote", REGISTRY_REMOTE),
            ("--mixed", REGISTRY_MIXED),
        ],
    )
    def test_explicit_flag_overrides_default(
        self, default_registry: str, flag: str, expected: str
    ) -> None:
        """Test that an explicit flag overrides any configured default."""
        cmd = self._make_command(default_registry)
        result = CliRunner().invoke(cmd, [flag])
        assert result.exit_code == 0
        assert result.output.strip() == expected


class TestRemoteRegistryFlag:
    """Tests for remote_registry_flag decorator with different defaults."""

    @staticmethod
    def _make_command(default_registry: str) -> click.Command:
        """Create a click command decorated with remote_registry_flag."""

        @click.command()
        @remote_registry_flag(default_registry=default_registry)
        def cmd(remote_registry: str) -> None:
            click.echo(remote_registry)

        return cmd

    @pytest.mark.parametrize(
        "default_registry",
        [REMOTE_IPFS, REMOTE_HTTP],
    )
    def test_no_flag_uses_configured_default(self, default_registry: str) -> None:
        """Test that omitting flags yields the configured default."""
        cmd = self._make_command(default_registry)
        result = CliRunner().invoke(cmd, [])
        assert result.exit_code == 0
        assert result.output.strip() == default_registry

    @pytest.mark.parametrize(
        "default_registry",
        [REMOTE_IPFS, REMOTE_HTTP],
    )
    @pytest.mark.parametrize(
        "flag,expected",
        [
            ("--ipfs", REMOTE_IPFS),
            ("--http", REMOTE_HTTP),
        ],
    )
    def test_explicit_flag_overrides_default(
        self, default_registry: str, flag: str, expected: str
    ) -> None:
        """Test that an explicit flag overrides any configured default."""
        cmd = self._make_command(default_registry)
        result = CliRunner().invoke(cmd, [flag])
        assert result.exit_code == 0
        assert result.output.strip() == expected
