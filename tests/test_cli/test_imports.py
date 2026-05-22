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

"""Tests guarding the import-time side effects of the ``aea.cli`` package."""

import json
import subprocess  # nosec
import sys
import textwrap


def test_importing_aea_cli_does_not_install_root_handler() -> None:
    """``import aea.cli`` must not attach any handler to the root logger.

    The agent's ``logging_config`` is applied via ``logging.config.dictConfig``
    when ``AEABuilder.build()`` is called. Any handler attached to the root
    logger before that point survives the ``dictConfig`` call (the agent's
    config block has no ``root:`` key) and produces duplicated log output:
    one copy via the agent's configured ``aea``-logger handlers, one copy
    via the orphan root handler that propagation also reaches.

    The intentional ``aea``-logger handler installed by
    ``aea/cli/utils/loggers.py`` is *not* a problem because the agent's
    ``dictConfig`` non-incremental mode replaces it cleanly when it
    applies a ``loggers.aea`` block. The bug is solely the root-logger
    orphan, which is what this test pins.

    The test runs in a subprocess so it observes the *clean* state of the
    interpreter immediately after ``import aea.cli``, independent of any
    handlers the test runner itself may have attached.
    """
    code = textwrap.dedent("""
        import json
        import logging
        import aea.cli  # noqa: F401
        root = logging.getLogger()
        print(json.dumps([type(h).__name__ for h in root.handlers]))
        """)
    output = (
        subprocess.check_output([sys.executable, "-c", code]).decode().strip()  # nosec
    )
    handlers = json.loads(output.splitlines()[-1])
    assert handlers == [], (
        "Importing 'aea.cli' installed root logger handlers: "
        f"{handlers}. This re-introduces the duplicate-log bug fixed by "
        "removing the import-time logging.basicConfig calls."
    )


def test_agent_log_record_is_not_duplicated_in_combined_stdout_stderr() -> None:
    """End-to-end regression test for the user-visible symptom of #914.

    Reproduces the agent runtime path: ``import aea.cli`` (which pre-fix
    installed a stderr root handler via two distinct module-top
    ``basicConfig`` sources), then applies the same ``logging_config``
    block the issue quotes from a real ``aea-config.yaml`` via
    ``logging.config.dictConfig`` (which is what ``AEABuilder.build()``
    does), then emits a log record under ``aea.agent.*`` (the namespace
    skills use through ``AgentLoggerAdapter``).

    The capture has to be OS-level ``2>&1`` because ``basicConfig`` binds
    ``sys.stderr`` at import time -- an in-process ``sys.stderr`` swap
    would not catch the orphan handler's output. So the assertion runs
    over the merged stream the operator would actually see when running
    ``aea -s run 2>&1 | tee agent.log``.

    Pre-fix this lands the marker twice (once via the agent's configured
    stdout handler, once via the orphan stderr root handler). Post-fix
    it lands exactly once.
    """
    marker = "regression_914_marker_xyz"
    code = textwrap.dedent(f"""
        import logging
        import logging.config
        import aea.cli  # noqa: F401

        # The logging_config block quoted from a real aea-config.yaml in
        # the issue #914 report:
        cfg = {{
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {{
                "standard": {{
                    "format": "[%(asctime)s] [%(levelname)s] %(message)s",
                }},
            }},
            "handlers": {{
                "console": {{
                    "class": "logging.StreamHandler",
                    "formatter": "standard",
                    "stream": "ext://sys.stdout",
                }},
            }},
            "loggers": {{
                "aea": {{
                    "level": "INFO",
                    "handlers": ["console"],
                    "propagate": True,
                }},
            }},
        }}
        logging.config.dictConfig(cfg)
        logging.getLogger("aea.agent.demo").info("{marker}")
        """)
    result = subprocess.run(  # nosec
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # merge so we see what the operator sees
        check=True,
    )
    combined = result.stdout.decode()
    occurrences = combined.count(marker)
    assert occurrences == 1, (
        f"Expected the agent log record to appear exactly once in combined "
        f"stdout+stderr; got {occurrences}. Full combined output:\n{combined}"
    )
