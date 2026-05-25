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
"""Logging helpers."""

import logging
from logging import Logger, LoggerAdapter
from typing import Any, MutableMapping, Optional, Tuple, cast

from aea.helpers.base import _get_aea_logger_name_prefix

DEFAULT_FORMAT = "[%(asctime)s][%(levelname)s] %(message)s"


def setup_logger(
    name: str, level: int = logging.INFO, log_format: str = DEFAULT_FORMAT
) -> Logger:
    """Set up the logger.

    Kept as a public helper for downstream consumers outside this repo;
    new in-repo callers should prefer ``logging.getLogger(name)`` and set
    the level directly. Calling ``logging.basicConfig`` at module-import
    time pollutes the root logger and was the cause of the duplicate-log
    bug fixed in #914 (PR #917).

    :param name: logger name.
    :param level: log level applied to the returned logger.
    :param log_format: format string passed to ``logging.basicConfig``.
        Only takes effect on the first call when the root logger has no
        handlers yet; subsequent calls are a no-op for the format.
    :return: the configured logger.
    """
    logging.basicConfig(format=log_format)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    return logger


def get_logger(module_path: str, agent_name: str) -> Logger:
    """Get the logger based on a module path and agent name."""
    logger = logging.getLogger(_get_aea_logger_name_prefix(module_path, agent_name))
    return logger


class AgentLoggerAdapter(LoggerAdapter):
    """This class is a logger adapter that prepends the agent name to log messages."""

    def __init__(self, logger: Logger, agent_name: str) -> None:
        """
        Initialize the logger adapter.

        :param logger: the logger.
        :param agent_name: the agent name.
        """
        super().__init__(logger, dict(agent_name=agent_name))

    def process(
        self, msg: Any, kwargs: MutableMapping[str, Any]
    ) -> Tuple[Any, MutableMapping[str, Any]]:
        """Prepend the agent name to every log message."""
        if self.extra is None:
            return msg, kwargs

        return f"[{self.extra['agent_name']}] {msg}", kwargs


class WithLogger:
    """Interface to endow subclasses with a logger."""

    __slots__ = ("_logger", "_default_logger_name")

    def __init__(
        self,
        logger: Optional[Logger] = None,
        default_logger_name: str = "aea",
    ) -> None:
        """
        Initialize the logger.

        :param logger: the logger object.
        :param default_logger_name: the default logger name, if a logger is not provided.
        """
        self._logger: Optional[Logger] = logger
        self._default_logger_name = default_logger_name

    @property
    def logger(self) -> Logger:
        """Get the component logger."""
        if self._logger is None:
            # if not set (e.g. programmatic instantiation)
            # return a default one with the default logger name.
            return logging.getLogger(self._default_logger_name)
        return cast(Logger, self._logger)

    @logger.setter
    def logger(self, logger: Optional[Logger]) -> None:
        """Set the logger."""
        self._logger = logger
