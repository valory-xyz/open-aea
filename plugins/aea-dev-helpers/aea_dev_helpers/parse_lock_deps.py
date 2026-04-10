# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2026 Valory AG
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

"""Parse main dependencies from a Pipfile.lock and output in requirements.txt format."""

import json
from pathlib import Path
from typing import Optional


def parse_lock_deps(pipfile_lock_path: str, output: Optional[str] = None) -> str:
    """
    Parse a Pipfile.lock and return requirements in requirements.txt format.

    :param pipfile_lock_path: path to the Pipfile.lock file.
    :param output: optional path to write the output to. If None, returns the string.
    :return: the requirements string.
    """
    pipfile_lock = Path(pipfile_lock_path)
    with open(pipfile_lock, "r") as f:
        pipfile_lock_content = json.load(f)

    requirements = sorted(
        map(
            lambda x: x[0] + x[1]["version"],
            pipfile_lock_content.get("default").items(),
        )
    )

    requirements_content = "\n".join(requirements)

    if output is not None:
        output_path = Path(output)
        with open(output_path, "w") as f:
            f.write(requirements_content)
    else:
        print(requirements_content)

    return requirements_content
