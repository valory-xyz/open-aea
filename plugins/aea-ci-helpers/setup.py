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

from setuptools import find_packages, setup  # type: ignore

setup(
    name="open-aea-ci-helpers",
    version="2.1.0",
    author="Valory AG",
    license="Apache-2.0",
    description="CI helper utilities for AEA-based projects.",
    long_description="CI helper utilities for AEA-based projects.",
    long_description_content_type="text/markdown",
    packages=find_packages(where=".", include=["aea_ci_helpers", "aea_ci_helpers.*"]),
    entry_points={
        "console_scripts": [
            "aea-ci=aea_ci_helpers.cli:cli",
        ],
    },
    install_requires=[
        "click>=8.1.0,<9",
        "packaging",
        "toml>=0.10,<1",
        "tomli",
    ],
    python_requires=">=3.10",
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
