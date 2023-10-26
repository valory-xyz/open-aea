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

"""Contains the AEA package."""

# pylint: disable=wrong-import-position

import inspect
import os
import sys


# Patch to fix https://github.com/protocolbuffers/protobuf/issues/3276

_google_upb_message = sys.modules.pop("google._upb._message", None)

from google.protobuf import struct_pb2 as google_dot_protobuf_dot_struct__pb2


if _google_upb_message is not None:
    sys.modules["google._upb._message"] = _google_upb_message


from packaging.version import Version

import aea.crypto  # triggers registry population
from aea.__version__ import (
    __author__,
    __copyright__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
)
from aea.crypto.plugin import load_all_plugins


AEA_DIR = os.path.dirname(inspect.getfile(inspect.currentframe()))  # type: ignore

load_all_plugins()


def get_current_aea_version() -> Version:
    """Get current version."""
    return Version(__version__)
