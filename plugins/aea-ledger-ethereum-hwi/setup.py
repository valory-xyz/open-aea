#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2023-2025 Valory AG
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

"""Setup script for "aea_ledger_ethereum_hwi" package."""

from setuptools import find_packages, setup


setup(
    name="open-aea-ledger-ethereum-hwi",
    version="2.0.0",
    author="Valory AG",
    license="Apache-2.0",
    description="Python package wrapping the public and private key cryptography and support for hardware wallet interactions.",
    long_description="Python package wrapping the public and private key cryptography and support for hardware wallet interactions.",
    long_description_content_type="text/markdown",
    packages=find_packages(include=["aea_ledger_ethereum_hwi*"]),
    package_data={
        "aea_ledger_ethereum_hwi": [
            "py.typed",
        ]
    },
    install_requires=[
        "open-aea>=2.0.0, <3.0.0",
        "web3>=6.0.0,<7",
        "ipfshttpclient==0.8.0a2",
        "eth-account>=0.8.0,<0.9.0",
        "open-aea-ledger-ethereum~=2.0.0",
        "ledgerwallet==0.1.3",
        "protobuf<4.25.0,>=4.21.6",
        "construct<=2.10.61",
    ],
    tests_require=["pytest"],
    entry_points={
        "aea.cryptos": ["ethereum_hwi = aea_ledger_ethereum_hwi:EthereumHWICrypto"],
        "aea.ledger_apis": ["ethereum_hwi = aea_ledger_ethereum_hwi:EthereumHWIApi"],
        "aea.faucet_apis": [
            "ethereum_hwi = aea_ledger_ethereum_hwi:EthereumHWIFaucetApi"
        ],
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
