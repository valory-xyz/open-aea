#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021 Valory AG
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
"""
This script is replacement for the `gcloud auth configure-docker` command.

which is *not* available in older versions of the gcloud commandline, what
is the case for our jenkins slave docker image which has older version.
"""

import json
import os


def ensure_directory_path_exists(file_path):
    """Ensure directory exists."""
    dir_path = os.path.dirname(file_path)

    try:
        os.makedirs(dir_path)
    except OSError:
        if not os.path.isdir(dir_path):
            raise


def write_dictionary_to_json_file(file_path, config_dict):
    """Write to json file."""
    ensure_directory_path_exists(file_path)

    with open(file_path, "w+") as config_file_descriptor:
        json.dump(config_dict, config_file_descriptor, indent=4)


def read_json_file_to_dictionary(file_path=None):
    """Read from file."""
    try:
        with open(file_path, "r") as config_file_descriptor:
            return json.load(config_file_descriptor)
    except IOError:
        return {}


def add_cred_helpers_to_config_file(file_path=None):
    """Add cred helpers to config file."""
    file_path = (
        os.path.join(os.path.expanduser("~"), ".docker/config.json")
        if file_path is None
        else file_path
    )
    config = read_json_file_to_dictionary(file_path)
    print(
        "Original content of the `{}` file:\n"
        "{}".format(file_path, json.dumps(config, indent=4))
    )

    default_cred_helper = "gcloud"

    expected_default_cred_helpers = {
        "gcr.io": default_cred_helper,
        "eu.gcr.io": default_cred_helper,
        "us.gcr.io": default_cred_helper,
        "staging-k8s.gcr.io": default_cred_helper,
        "asia.gcr.io": default_cred_helper,
    }

    cred_helpers_key = "credHelpers"
    if cred_helpers_key in config:
        cred_helpers = config[cred_helpers_key]
    else:
        cred_helpers = {}
        config[cred_helpers_key] = cred_helpers

    for registry, cred_helper in expected_default_cred_helpers.items():
        cred_helpers[registry] = cred_helper

    write_dictionary_to_json_file(file_path, config)
    print(
        "Content of the `{}` file after adding credential helpers:\n"
        "{}".format(file_path, json.dumps(config, indent=4))
    )


add_cred_helpers_to_config_file()
