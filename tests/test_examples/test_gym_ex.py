# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2025 Valory AG
#   Copyright 2018-2020 Fetch.AI Limited
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
"""The tests module contains the tests of the gym example."""

import os
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from aea.configurations.base import ConnectionConfig
from aea.identity.base import Identity

from packages.fetchai.connections.gym.connection import GymConnection

from tests.common.pexpect_popen import PexpectWrapper
from tests.conftest import ROOT_DIR, env_path_separator


DIRECTORIES = ["packages", "examples"]


class TestGymExt:
    """Test the gym example."""

    @classmethod
    def setup_class(cls):
        """Set up the test class."""
        cls.old_cwd = Path(os.getcwd())
        cls.t = Path(tempfile.mkdtemp())
        for directory in DIRECTORIES:
            dir_path = Path(directory)
            tmp_dir = cls.t / dir_path
            src_dir = cls.old_cwd / Path(ROOT_DIR, directory)
            shutil.copytree(str(src_dir), str(tmp_dir))
        os.chdir(Path(cls.t))

    def test_gym_ex(self):
        """Run the gym ex sequence."""
        try:
            env = os.environ.copy()
            env["PYTHONPATH"] = (
                f"{self.t}{env_path_separator()}{env.get('PYTHONPATH', '')}"
            )
            process = PexpectWrapper(  # nosec
                [
                    sys.executable,
                    str(Path("examples/gym_ex/train.py").resolve()),
                    "--nb-steps",
                    "50",
                ],
                env=env,
                maxread=1,
                encoding="utf-8",
                logfile=sys.stdout,
            )

            process.expect(["Step 50/50"], timeout=10)
            process.wait_to_complete(5)
            assert process.returncode == 0, "Test failed"
        finally:
            process.terminate()
            process.wait_to_complete(5)

    @classmethod
    def teardown_class(cls):
        """Teardown the test."""
        try:
            os.chdir(Path(cls.old_cwd))
            shutil.rmtree(cls.t)
        except (OSError, IOError):
            pass


def test_gym_env_load():
    """Load gym env from file."""
    try:
        curdir = os.getcwd()
        os.chdir(os.path.join(ROOT_DIR, "examples", "gym_ex"))
        gym_env_path = "gyms.env.BanditNArmedRandom"
        configuration = ConnectionConfig(
            connection_id=GymConnection.connection_id, env=gym_env_path
        )
        identity = Identity(
            "name", address="agent_address", public_key="agent_public_key"
        )
        gym_con = GymConnection(
            gym_env=None,
            identity=identity,
            configuration=configuration,
            data_dir=MagicMock(),
        )
        assert gym_con.channel.gym_env is not None
    finally:
        os.chdir(curdir)
