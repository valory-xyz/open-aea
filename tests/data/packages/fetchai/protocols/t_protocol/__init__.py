# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2025 fetchai
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

"""
This module contains the support resources for the t_protocol protocol.

It was created with protocol buffer compiler version `libprotoc 24.3` and aea protocol generator version `1.0.0`.
"""

from tests.data.packages.fetchai.protocols.t_protocol.message import TProtocolMessage
from tests.data.packages.fetchai.protocols.t_protocol.serialization import (
    TProtocolSerializer,
)


TProtocolMessage.serializer = TProtocolSerializer
