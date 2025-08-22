#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2025 Valory AG
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


"""Setup script for the plug-in."""


from setuptools import setup  # type: ignore


setup(
    name="open-aea-cli-ipfs",
    version="2.0.5",
    author="Valory AG",
    license="Apache-2.0",
    description="CLI extension for open AEA framework wrapping IPFS functionality.",
    long_description="CLI extension for open AEA framework wrapping IPFS functionality.",
    long_description_content_type="text/markdown",
    packages=["aea_cli_ipfs"],
    package_data={"aea_cli_ipfs": ["py.typed"]},
    entry_points={"aea.cli": ["ipfs_cli_command = aea_cli_ipfs.core:ipfs"]},
    install_requires=[
        "open-aea>=2.0.0, <3.0.0",
        "ipfshttpclient>=0.8.0a2",
    ],
    tests_require=["pytest"],
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
