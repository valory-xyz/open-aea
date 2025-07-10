# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2025 Valory AG
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

"""This test module contains the tests for the `aea generate-key` sub-command."""
import json
import os
import random
import shutil
import string
import tempfile
from pathlib import Path
from typing import Type

import pytest
from aea_ledger_cosmos import CosmosCrypto
from aea_ledger_ethereum import EthereumCrypto
from aea_ledger_ethereum.test_tools.constants import ETHEREUM_PRIVATE_KEY_FILE
from aea_ledger_fetchai import FetchAICrypto
from aea_ledger_fetchai.test_tools.constants import FETCHAI_PRIVATE_KEY_FILE

from aea.cli import cli
from aea.configurations.constants import MULTIKEY_FILENAME
from aea.crypto.base import Crypto as BaseCrypto
from aea.crypto.registries import crypto_registry, make_crypto
from aea.helpers.io import open_file
from aea.helpers.sym_link import cd
from aea.test_tools.test_cases import AEATestCaseEmpty

from tests.conftest import CLI_LOG_OPTION, CliRunner


class TestGenerateKey:
    """Test that the command 'aea generate-key' works as expected."""

    @classmethod
    def setup_class(cls):
        """Set the test up."""
        cls.runner = CliRunner()
        cls.agent_name = "myagent"
        cls.cwd = os.getcwd()
        cls.t = tempfile.mkdtemp()
        os.chdir(cls.t)

    def test_fetchai(self, password_or_none):
        """Test that the fetch private key is created correctly."""
        args = [*CLI_LOG_OPTION, "generate-key", FetchAICrypto.identifier] + (
            ["--password", password_or_none] if password_or_none is not None else []
        )
        result = self.runner.invoke(cli, args)
        assert result.exit_code == 0
        assert Path(FETCHAI_PRIVATE_KEY_FILE).exists()
        make_crypto(
            FetchAICrypto.identifier,
            private_key_path=FETCHAI_PRIVATE_KEY_FILE,
            password=password_or_none,
        )

        Path(FETCHAI_PRIVATE_KEY_FILE).unlink()

    def test_ethereum(self, password_or_none):
        """Test that the fetch private key is created correctly."""
        args = [*CLI_LOG_OPTION, "generate-key", EthereumCrypto.identifier] + (
            ["--password", password_or_none] if password_or_none is not None else []
        )
        result = self.runner.invoke(cli, args)
        assert result.exit_code == 0
        assert Path(ETHEREUM_PRIVATE_KEY_FILE).exists()
        make_crypto(
            EthereumCrypto.identifier,
            private_key_path=ETHEREUM_PRIVATE_KEY_FILE,
            password=password_or_none,
        )

        Path(ETHEREUM_PRIVATE_KEY_FILE).unlink()

    def test_all(self):
        """Test that all the private keys are created correctly when running 'aea generate-key all'."""
        result = self.runner.invoke(cli, [*CLI_LOG_OPTION, "generate-key", "all"])
        assert result.exit_code == 0

        assert Path(FETCHAI_PRIVATE_KEY_FILE).exists()
        assert Path(ETHEREUM_PRIVATE_KEY_FILE).exists()
        make_crypto(FetchAICrypto.identifier, private_key_path=FETCHAI_PRIVATE_KEY_FILE)
        make_crypto(
            EthereumCrypto.identifier, private_key_path=ETHEREUM_PRIVATE_KEY_FILE
        )

        Path(FETCHAI_PRIVATE_KEY_FILE).unlink()
        Path(ETHEREUM_PRIVATE_KEY_FILE).unlink()

    def test_invalid_ledger_id(self):
        """Test that the fetch private key is created correctly."""
        args = [*CLI_LOG_OPTION, "generate-key", "ledger"]
        result = self.runner.invoke(cli, args)
        assert result.exit_code == 1
        assert "Invalid identifier provided `ledger`" in result.stderr

    def test_no_ledger_installation_found(self):
        """Test that the fetch private key is created correctly."""
        args = [*CLI_LOG_OPTION, "generate-key", "ledger"]
        specs = crypto_registry.specs.copy()
        crypto_registry.specs = {}
        try:
            result = self.runner.invoke(cli, args)
            assert result.exit_code == 1
            assert "No ledger installation found" in result.stderr
        finally:
            crypto_registry.specs = specs

    @classmethod
    def teardown_class(cls):
        """Tear the test down."""
        os.chdir(cls.cwd)
        shutil.rmtree(cls.t)


class TestGenerateKeyWhenAlreadyExists:
    """Test that the command 'aea generate-key' asks for confirmation when a key already exists."""

    @classmethod
    def setup_class(cls):
        """Set the test up."""
        cls.runner = CliRunner()
        cls.agent_name = "myagent"
        cls.cwd = os.getcwd()
        cls.t = tempfile.mkdtemp()
        os.chdir(cls.t)

    def test_fetchai(self):
        """Test that the fetchai private key is overwritten or not dependending on the user input."""
        result = self.runner.invoke(
            cli, [*CLI_LOG_OPTION, "generate-key", FetchAICrypto.identifier]
        )
        assert result.exit_code == 0
        assert Path(FETCHAI_PRIVATE_KEY_FILE).exists()

        # This tests if the file has been created and its content is correct.
        make_crypto(FetchAICrypto.identifier, private_key_path=FETCHAI_PRIVATE_KEY_FILE)
        content = Path(FETCHAI_PRIVATE_KEY_FILE).read_bytes()

        # Saying 'no' leave the files as it is.
        result = self.runner.invoke(
            cli, [*CLI_LOG_OPTION, "generate-key", FetchAICrypto.identifier], input="n"
        )
        assert result.exit_code == 0
        assert Path(FETCHAI_PRIVATE_KEY_FILE).read_bytes() == content

        # Saying 'yes' overwrites the file.
        result = self.runner.invoke(
            cli, [*CLI_LOG_OPTION, "generate-key", FetchAICrypto.identifier], input="y"
        )
        assert result.exit_code == 0
        assert Path(FETCHAI_PRIVATE_KEY_FILE).read_bytes() != content
        make_crypto(FetchAICrypto.identifier, private_key_path=FETCHAI_PRIVATE_KEY_FILE)

    @classmethod
    def teardown_class(cls):
        """Tear the test down."""
        os.chdir(cls.cwd)
        shutil.rmtree(cls.t)


class TestGenerateKeyWithFile:
    """Test that the command 'aea generate-key' can accept a file path."""

    @classmethod
    def setup_class(cls):
        """Set the test up."""
        cls.runner = CliRunner()
        cls.agent_name = "myagent"
        cls.cwd = os.getcwd()
        cls.t = tempfile.mkdtemp()
        os.chdir(cls.t)

    def test_fetchai(self):
        """Test that the fetchai private key can be deposited in a custom file."""
        test_file = "test.txt"
        result = self.runner.invoke(
            cli, [*CLI_LOG_OPTION, "generate-key", FetchAICrypto.identifier, test_file]
        )
        assert result.exit_code == 0
        assert Path(test_file).exists()

        # This tests if the file has been created and its content is correct.
        crypto = make_crypto(FetchAICrypto.identifier, private_key_path=test_file)
        content = Path(test_file).read_bytes()
        assert content.decode("utf-8") == crypto.private_key

    def test_all(self):
        """Test that the all command does not allow a file to be provided."""
        test_file = "test.txt"
        result = self.runner.invoke(
            cli, [*CLI_LOG_OPTION, "generate-key", "all", test_file]
        )
        assert result.exit_code == 1

    @classmethod
    def teardown_class(cls):
        """Tear the test down."""
        os.chdir(cls.cwd)
        shutil.rmtree(cls.t)


class TestGenerateKeyWithAddKeyWithoutConnection(AEATestCaseEmpty):
    """Test that the command 'aea generate-key --add-key' works as expected."""

    keys_config_path = "agent.private_key_paths"
    args = []  # type: ignore

    def test_fetchai(self):
        """Test that the fetch private key is created correctly."""

        with cd(self._get_cwd()):
            result = self.run_cli_command(
                "config", "get", self.keys_config_path, cwd=self._get_cwd()
            )
            assert result.exit_code == 0
            assert json.loads(result.stdout_bytes) == {}

            args = [*CLI_LOG_OPTION, "generate-key", FetchAICrypto.identifier]
            result = self.run_cli_command(
                *args, "--add-key", *self.args, cwd=self._get_cwd()
            )
            assert result.exit_code == 0
            assert Path(FETCHAI_PRIVATE_KEY_FILE).exists()
            make_crypto(
                FetchAICrypto.identifier,
                private_key_path=FETCHAI_PRIVATE_KEY_FILE,
                password=None,
            )

            Path(FETCHAI_PRIVATE_KEY_FILE).unlink()

            result = self.run_cli_command(
                "config", "get", self.keys_config_path, cwd=self._get_cwd()
            )
            assert result.exit_code == 0
            agent_keys = json.loads(result.stdout_bytes)
            assert agent_keys.get(FetchAICrypto.identifier) == FETCHAI_PRIVATE_KEY_FILE


class TestGenerateKeyWithAddKeyWithConnection(
    TestGenerateKeyWithAddKeyWithoutConnection
):
    """Test that the command 'aea generate-key --add-key' works as expected."""

    keys_config_path = "agent.connection_private_key_paths"
    args = ["--connection"]  # type: ignore


class TestGenerateN(AEATestCaseEmpty):
    """Test generate N keys."""

    n = 5

    @pytest.mark.parametrize(
        argnames="crypto", argvalues=(EthereumCrypto, FetchAICrypto, CosmosCrypto)
    )
    def test_generate_without_password(
        self,
        crypto: Type[BaseCrypto],
    ) -> None:
        """Test generate keys without password."""

        with tempfile.TemporaryDirectory() as temp_dir:
            outfile = Path(temp_dir, crypto.identifier)
            result = self.run_cli_command(
                "generate-key",
                crypto.identifier,
                str(outfile),
                "-n",
                f"{self.n}",
                cwd=str(self.t),
            )

            assert result.exit_code == 0
            assert outfile.exists()

            keys = json.loads(outfile.read_text())
            assert len(keys) == self.n

    def test_generate_default_file(
        self,
    ) -> None:
        """Test generate default output file."""

        outfile = Path(self.t, MULTIKEY_FILENAME)
        result = self.run_cli_command(
            "generate-key",
            EthereumCrypto.identifier,
            "-n",
            f"{self.n}",
            cwd=str(self.t),
        )

        assert result.exit_code == 0
        assert outfile.exists()

        keys = json.loads(outfile.read_text())
        assert len(keys) == self.n

    @pytest.mark.parametrize(
        argnames="crypto", argvalues=(EthereumCrypto, FetchAICrypto, CosmosCrypto)
    )
    def test_generate_with_password(
        self,
        crypto: Type[BaseCrypto],
    ) -> None:
        """Test generate keys without password."""

        password = "".join(
            [random.choice(string.ascii_letters) for _ in range(10)],  # nosec
        )

        with tempfile.TemporaryDirectory() as temp_dir:
            outfile = Path(temp_dir, crypto.identifier)
            result = self.run_cli_command(
                "generate-key",
                crypto.identifier,
                str(outfile),
                "-n",
                f"{self.n}",
                "--password",
                password,
                cwd=str(self.t),
            )

            assert result.exit_code == 0
            assert outfile.exists()

            keys = json.loads(outfile.read_text())
            assert len(keys) == self.n

            for idx, key in enumerate(keys):
                key_file = f"{crypto.identifier}_{idx}.txt"
                with open_file(key_file, "w") as fp:
                    fp.write(key["private_key"])

                crypto_obj = crypto(private_key_path=key_file, password=password)
                assert crypto_obj.address == key["address"]
