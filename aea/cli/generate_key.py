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
"""Implementation of the 'aea generate_key' subcommand."""
import json
from pathlib import Path
from typing import Dict, Optional, Union

import click

from aea.cli.add_key import _add_private_key
from aea.cli.utils.click_utils import LedgerChoice, password_option
from aea.cli.utils.decorators import _check_aea_project
from aea.configurations.constants import (
    ADDRESS,
    LEDGER,
    MULTIKEY_FILENAME,
    PRIVATE_KEY,
    PRIVATE_KEY_PATH_SCHEMA,
)
from aea.crypto.helpers import create_private_key
from aea.crypto.registries import crypto_registry, make_crypto


@click.command()
@click.argument(
    "type_",
    metavar="TYPE",
    type=LedgerChoice(),
    required=True,
)
@click.argument(
    "file",
    metavar="FILE",
    type=click.Path(exists=False, file_okay=True, dir_okay=False, readable=True),
    required=False,
)
@password_option(confirmation_prompt=True)
@click.option(
    "--add-key",
    is_flag=True,
    help="Add generated key.",
)
@click.option(
    "--connection", is_flag=True, help="For adding a private key for connections."
)
@click.option(
    "--extra-entropy",
    type=str,
    required=False,
    default="",
)
@click.option("-n", type=int, help="Number of keys to generate")
@click.pass_context
def generate_key(  # pylint: disable=too-many-positional-arguments
    click_context: click.core.Context,
    type_: str,
    file: str,
    password: Optional[str],
    add_key: bool = False,
    connection: bool = False,
    extra_entropy: Union[str, bytes, int] = "",
    n: Optional[int] = None,
) -> None:
    """Generate a private key and place it in a file."""
    if n is None:
        _generate_one(
            click_context=click_context,
            type_=type_,
            file=file,
            password=password,
            add_key=add_key,
            connection=connection,
            extra_entropy=extra_entropy,
        )
        return

    _generate_multiple_keys(
        n=n,
        type_=type_,
        password=password,
        extra_entropy=extra_entropy,
        file=file,
    )


def _generate_one(  # pylint: disable=too-many-positional-arguments
    click_context: click.core.Context,
    type_: str,
    file: str,
    password: Optional[str],
    add_key: bool = False,
    connection: bool = False,
    extra_entropy: Union[str, bytes, int] = "",
) -> None:
    """Generate one key."""
    keys_generated = _generate_private_key(type_, file, password, extra_entropy)
    if add_key:
        _check_aea_project((click_context,))
        for key_type, key_filename in keys_generated.items():
            _add_private_key(
                click_context, key_type, key_filename, password, connection
            )


def _generate_private_key(
    type_: str,
    file: Optional[str] = None,
    password: Optional[str] = None,
    extra_entropy: Union[str, bytes, int] = "",
) -> Dict[str, str]:
    """
    Generate private key.

    :param type_: type.
    :param file: path to file.
    :param password: the password to encrypt/decrypt the private key.
    :param extra_entropy: add extra randomness to whatever randomness your OS can provide

    :return: dict of types and filenames of keys generated
    """
    keys = {}
    if type_ == "all" and file is not None:
        raise click.ClickException("Type all cannot be used in combination with file.")
    types = list(crypto_registry.supported_ids) if type_ == "all" else [type_]
    for type__ in types:
        private_key_file = (
            PRIVATE_KEY_PATH_SCHEMA.format(type__) if file is None else file
        )
        if _can_write(private_key_file):
            create_private_key(type__, private_key_file, password, extra_entropy)
        keys[type__] = private_key_file
    return keys


def _generate_multiple_keys(
    n: int,
    type_: str,
    password: Optional[str] = None,
    extra_entropy: Union[str, bytes, int] = "",
    file: Optional[str] = None,
) -> None:
    """Generate n key pairs."""

    key_pairs = []
    for _ in range(n):
        crypto = make_crypto(type_, extra_entropy=extra_entropy)
        priv_key = (
            crypto.encrypt(password=password)
            if password is not None
            else crypto.private_key
        )
        key_pairs.append(
            {ADDRESS: crypto.address, PRIVATE_KEY: priv_key, LEDGER: type_}
        )

    file = file or MULTIKEY_FILENAME
    if _can_write(file):
        Path(file).write_text(json.dumps(obj=key_pairs, indent=2), encoding="utf-8")


def _can_write(path: str) -> bool:
    if Path(path).exists():
        value = click.confirm(
            "The file {} already exists. Do you want to overwrite it?".format(path),
            default=False,
        )
        return value
    return True
