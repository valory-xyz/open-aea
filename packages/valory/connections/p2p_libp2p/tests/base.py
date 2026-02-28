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

"""Constants, utility functions and base classes for ACN p2p_libp2p tests"""

import functools
import inspect
import itertools
import platform
import tempfile
from typing import Any, Callable, Type
from unittest import mock

import pytest

from packages.fetchai.protocols.default.message import DefaultMessage

TIMEOUT = 20
TEMP_LIBP2P_TEST_DIR = tempfile.mkdtemp()
ports = itertools.count(10234)

MockDefaultMessageProtocol = mock.Mock()
MockDefaultMessageProtocol.protocol_id = DefaultMessage.protocol_id
MockDefaultMessageProtocol.protocol_specification_id = (
    DefaultMessage.protocol_specification_id
)

SKIP_WINDOWS = pytest.mark.skipif(
    condition=(platform.system() == "Windows"),
    reason="https://github.com/golang/go/issues/51007",
)


def libp2p_log_on_failure(fn: Callable) -> Callable:
    """Decorate a method running a libp2p node to print its logs in case test fails."""

    @functools.wraps(fn)
    def wrapper(self, *args: Any, **kwargs: Any) -> None:  # type: ignore
        try:
            return fn(self, *args, **kwargs)
        except Exception:
            for log_file in getattr(self, "log_files", []):
                print(f"libp2p log file ======================= {log_file}")
                try:
                    with open(log_file, "r") as f:
                        print(f.read())
                except FileNotFoundError:
                    print("FileNotFoundError")
                print("=======================================")
            raise

    return wrapper


def libp2p_log_on_failure_all(cls: Type) -> Type:
    """Wrap test methods to print libp2p logs on failure."""

    def _wrap(func: Callable) -> Callable:
        if inspect.iscoroutinefunction(func):

            @functools.wraps(func)
            async def _async_wrapped(*args: Any, **kwargs: Any) -> Any:
                return await func(*args, **kwargs)

            return _async_wrapped

        @functools.wraps(func)
        def _sync_wrapped(*args: Any, **kwargs: Any) -> Any:
            return func(*args, **kwargs)

        return _sync_wrapped

    for name, value in list(vars(cls).items()):
        if name.startswith("test_") and callable(value):
            setattr(cls, name, _wrap(value))

    return cls
