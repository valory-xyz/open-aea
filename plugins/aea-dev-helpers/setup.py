#!/usr/bin/env python3
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
"""Setup script for the plug-in."""

from pathlib import Path

from setuptools import find_packages, setup  # type: ignore


def _read_long_description() -> str:
    """Read the plugin README as the PyPI long description."""
    return (Path(__file__).parent / "README.md").read_text(encoding="utf-8")


setup(
    name="open-aea-dev-helpers",
    version="2.2.0",
    author="Valory AG",
    license="Apache-2.0",
    description="Development and release helper utilities for AEA-based projects.",
    long_description=_read_long_description(),
    long_description_content_type="text/markdown",
    packages=find_packages(include=["aea_dev_helpers*"]),
    entry_points={
        "console_scripts": [
            "aea-dev=aea_dev_helpers.cli:cli",
        ],
    },
    install_requires=[
        "click>=8.1.0,<8.4.0",
        "gitpython>=3.1.37,<4",
        "open-aea-cli-ipfs>=2.0.0,<3.0.0",
        "packaging>=22.0,<27",
        "pyyaml>=6.0.1,<7",
    ],
    python_requires=">=3.10,<3.15",
    classifiers=[
        "Environment :: Console",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
)
