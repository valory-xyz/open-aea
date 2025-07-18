#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2025 Valory AG
#   Copyright 2018-2019 Fetch.AI Limited
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
import os
import re
from typing import Dict

from setuptools import find_packages, setup  # type: ignore


PACKAGE_NAME = "aea"
here = os.path.abspath(os.path.dirname(__file__))


def get_all_extras() -> Dict:
    cli_deps = [
        "click>=8.1.0,<9",
        "pyyaml>=6.0.1,<9",
        "packaging>=23.1,<24.0",
        "pytest>=7.0.0,<7.3.0",
        "coverage>=6.4.4,<8.0.0",
        "jsonschema<4.4.0,>=4.3.0",
        "semver>=2.9.1,<3.0.0",
    ]

    extras = {
        "cli": cli_deps,
        "test_tools": cli_deps,
    }

    # add "all" extras
    extras["all"] = list(set(dep for e in extras.values() for dep in e))
    return extras


all_extras = get_all_extras()

base_deps = [
    "semver>=2.9.1,<3.0.0",
    "base58>=1.0.3,<3.0.0",
    "jsonschema<4.4.0,>=4.3.0",
    "packaging>=23.1,<24.0",
    "protobuf<4.25.0,>=4.21.6",
    "pymultihash==0.8.2",
    "pyyaml>=6.0.1,<7",
    "requests>=2.28.1,<3",
    "python-dotenv>=0.14.0,<1.0.1",
    "ecdsa>=0.15,<0.17.0",
    "morphys>=1.0",
    "py-multibase>=1.0.0",
    "py-multicodec>=0.2.0",
]

if os.name == "nt" or os.getenv("WIN_BUILD_WHEEL", None) == "1":
    base_deps.append("pywin32>=304")


here = os.path.abspath(os.path.dirname(__file__))
about: Dict[str, str] = {}
with open(os.path.join(here, PACKAGE_NAME, "__version__.py"), "r") as f:
    exec(f.read(), about)


def parse_readme():
    with open("README.md", "r") as f:
        readme = f.read()

    # replace relative links of images
    raw_url_root = "https://raw.githubusercontent.com/valory-xyz/open-aea/main/"
    replacement = raw_url_root + r"\g<0>"
    readme = re.sub(r"(?<=<img src=\")(/.*)(?=\")", replacement, readme, re.DOTALL)

    header = re.search("<h1.*?(?=## )", readme, re.DOTALL).group(0)
    get_started = re.search("## Get started.*?(?=## )", readme, re.DOTALL).group(0)
    cite = re.search("## Cite.*$", readme, re.DOTALL).group(0)
    return "\n".join([header, get_started, cite])


if __name__ == "__main__":
    setup(
        name=about["__title__"],
        description=about["__description__"],
        version=about["__version__"],
        author=about["__author__"],
        url=about["__url__"],
        long_description=parse_readme(),
        long_description_content_type="text/markdown",
        package_data={"aea": ["py.typed"]},
        packages=find_packages(include=["aea*"]),
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
            "Topic :: Scientific/Engineering",
            "Topic :: Software Development",
            "Topic :: System",
        ],
        install_requires=base_deps,
        tests_require=["tox"],
        extras_require=all_extras,
        entry_points={"console_scripts": ["aea=aea.cli:cli"]},
        zip_safe=False,
        include_package_data=True,
        license=about["__license__"],
        python_requires=">=3.10",
        keywords="aea open-aea autonomous-economic-agents agent-framework multi-agent-systems multi-agent cryptocurrency cryptocurrencies dezentralized dezentralized-network",
        project_urls={
            "Bug Reports": "https://github.com/valory-xyz/open-aea/issues",
            "Source": "https://github.com/valory-xyz/open-aea",
        },
    )
