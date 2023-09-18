# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2018-2019 Fetch.AI Limited
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

"""This module contains the implementation of command-line tool 'aea'."""

# pylint: disable=wrong-import-position

import sys


# Patch to fix https://github.com/protocolbuffers/protobuf/issues/3276

_google_upb_message = sys.modules.pop("google._upb._message")

from google.protobuf import struct_pb2 as google_dot_protobuf_dot_struct__pb2


sys.modules["google._upb._message"] = _google_upb_message

from .core import cli
