#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2025 Valory AG
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

"""Setup script for "aea_ledger_cosmos" package."""

from setuptools import find_packages, setup


setup(
    name="open-aea-ledger-cosmos",
    version="2.0.0",
    author="Valory AG",
    license="Apache-2.0",
    description="Python package wrapping the public and private key cryptography and ledger api of Cosmos.",
    long_description="Python package wrapping the public and private key cryptography and ledger api of Cosmos.",
    long_description_content_type="text/markdown",
    packages=find_packages(include=["aea_ledger_cosmos*"]),
    package_data={
        "aea_ledger_cosmos": [
            "py.typed",
        ]
    },
    install_requires=[
        "open-aea>=2.0.0, <3.0.0",
        "ecdsa>=0.15,<0.17.0",
        "bech32>=1.2.0,<2",
        "pycryptodome>=3.10.1,<4.0.0",
        "cosmpy==0.9.2",
    ],
    tests_require=["pytest"],
    entry_points={
        "aea.cryptos": ["cosmos = aea_ledger_cosmos:CosmosCrypto"],
        "aea.ledger_apis": ["cosmos = aea_ledger_cosmos:CosmosApi"],
        "aea.faucet_apis": ["cosmos = aea_ledger_cosmos:CosmosFaucetApi"],
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
        "Topic :: Communications",
        "Topic :: Internet",
        "Topic :: Software Development",
    ],
)
