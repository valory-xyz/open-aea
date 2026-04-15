#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2026 Valory AG
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

"""Setup script for "aea_ledger_ethereum" package."""

from pathlib import Path

from setuptools import find_packages, setup


def _read_long_description() -> str:
    """Read the plugin README as the PyPI long description."""
    return (Path(__file__).parent / "README.md").read_text(encoding="utf-8")


setup(
    name="open-aea-ledger-ethereum",
    version="2.2.1",
    author="Valory AG",
    license="Apache-2.0",
    description="Python package wrapping the public and private key cryptography and ledger api of Ethereum.",
    long_description=_read_long_description(),
    long_description_content_type="text/markdown",
    packages=find_packages(include=["aea_ledger_ethereum*"]),
    package_data={
        "aea_ledger_ethereum": [
            "py.typed",
            "test_tools/data/*",
        ]
    },
    python_requires=">=3.10,<3.15",
    install_requires=[
        "open-aea>=2.0.0, <3.0.0",
        "web3>=7.0.0,<8",
        "eth-account>=0.13.0,<0.14.0",
        "requests>=2.32.5,<3",
    ],
    extras_require={
        "test_tools": ["pytest>=7.0,<10", "docker==7.1.0"],
    },
    tests_require=["pytest>=7.0,<10"],
    entry_points={
        "aea.cryptos": ["ethereum = aea_ledger_ethereum:EthereumCrypto"],
        "aea.ledger_apis": ["ethereum = aea_ledger_ethereum:EthereumApi"],
        "aea.faucet_apis": ["ethereum = aea_ledger_ethereum:EthereumFaucetApi"],
    },
    classifiers=[
        "Environment :: Console",
        "Environment :: Web Environment",
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: Apache Software License",
        "Natural Language :: English",
        "Operating System :: MacOS",
        "Operating System :: Microsoft",
        "Operating System :: Unix",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Communications",
        "Topic :: Internet",
        "Topic :: Software Development",
    ],
)
