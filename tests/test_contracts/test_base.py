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

"""This module contains tests for aea.contracts.base."""
import logging
import os
import platform
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import cast
from unittest import mock
from unittest.mock import MagicMock

import pytest
import web3
from aea_ledger_ethereum import EthereumCrypto
from aea_ledger_ethereum.test_tools.constants import ETHEREUM_TESTNET_CONFIG
from aea_ledger_fetchai import FetchAICrypto

from aea.cli.scaffold import add_contract_abi, scaffold_item
from aea.cli.utils.context import Context
from aea.configurations.base import ComponentType, ContractConfig
from aea.configurations.constants import (  # noqa: F401  # pylint: disable=unused-import
    CONTRACT,
    CONTRACTS,
)
from aea.configurations.loader import load_component_configuration
from aea.contracts import contract_registry
from aea.contracts.base import Contract
from aea.contracts.scaffold.contract import MyScaffoldContract
from aea.crypto.ledger_apis import ETHEREUM_DEFAULT_ADDRESS, FETCHAI_DEFAULT_ADDRESS
from aea.crypto.registries import crypto_registry, ledger_apis_registry
from aea.exceptions import AEAComponentLoadException
from aea.package_manager.v1 import PackageManagerV1

from tests.conftest import ROOT_DIR, make_uri


logger = logging.getLogger(__name__)


def test_from_dir():
    """Tests the from dir and from config methods."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    assert contract is not None
    assert contract.contract_interface is not None
    assert isinstance(contract.contract_interface, dict)


def test_from_config_and_registration():
    """Tests the from config method and contract registry registration."""

    directory = Path(ROOT_DIR, "tests", "data", "dummy_contract")
    configuration = load_component_configuration(ComponentType.CONTRACT, directory)
    configuration._directory = directory
    configuration = cast(ContractConfig, configuration)

    if str(configuration.public_id) in contract_registry.specs:
        contract_registry.specs.pop(str(configuration.public_id))

    contract = Contract.from_config(configuration)
    assert contract is not None
    assert contract.contract_interface is not None
    assert isinstance(contract.contract_interface, dict)
    assert contract.configuration == configuration
    assert contract.id == configuration.public_id

    # the contract is registered as side-effect
    assert str(contract.public_id) in contract_registry.specs

    try:
        contract_registry.specs.pop(str(configuration.public_id))
    except Exception as e:
        logger.exception(e)


def test_from_config_negative():
    """Tests the from config method raises."""

    directory = Path(ROOT_DIR, "tests", "data", "dummy_contract")
    configuration = load_component_configuration(ComponentType.CONTRACT, directory)
    configuration._directory = directory
    configuration = cast(ContractConfig, configuration)

    if str(configuration.public_id) in contract_registry.specs:
        contract_registry.specs.pop(str(configuration.public_id))

    configuration.class_name = "WrongName"
    with pytest.raises(AEAComponentLoadException):
        _ = Contract.from_config(configuration)

    try:
        contract_registry.specs.pop(str(configuration.public_id))
    except Exception as e:
        logger.exception(e)


def test_non_implemented_class_methods():
    """Tests the non implemented class methods."""
    with pytest.raises(NotImplementedError):
        Contract.get_raw_transaction("ledger_api", "contract_address")

    with pytest.raises(NotImplementedError):
        Contract.get_raw_message("ledger_api", "contract_address")

    with pytest.raises(NotImplementedError):
        Contract.get_state("ledger_api", "contract_address")


@pytest.fixture()
def dummy_contract(request):
    """Dummy contract fixture."""
    directory = Path(ROOT_DIR, "tests", "data", "dummy_contract")
    configuration = load_component_configuration(ComponentType.CONTRACT, directory)
    configuration._directory = directory
    configuration = cast(ContractConfig, configuration)

    if str(configuration.public_id) in contract_registry.specs:
        contract_registry.specs.pop(str(configuration.public_id))

    # load into sys modules and register into contract registry
    contract = Contract.from_config(configuration)
    yield contract
    contract_registry.specs.pop(str(configuration.public_id))


def test_get_instance_no_address_ethereum(dummy_contract):
    """Tests get instance method with no address for ethereum."""
    ledger_api = ledger_apis_registry.make(
        EthereumCrypto.identifier,
        address=ETHEREUM_DEFAULT_ADDRESS,
    )
    instance = dummy_contract.get_instance(ledger_api)
    assert type(instance) is web3._utils.datatypes.PropertyCheckingFactory


@pytest.mark.integration
@pytest.mark.ledger
def test_get_deploy_transaction_ethereum(
    dummy_contract, ganache_addr, ganache_port, ganache
):
    """Tests the deploy transaction classmethod for ethereum."""
    aea_ledger_ethereum = crypto_registry.make(EthereumCrypto.identifier)
    config = ETHEREUM_TESTNET_CONFIG
    config.update(dict(address=make_uri(ganache_addr, ganache_port)))
    ledger_api = ledger_apis_registry.make(EthereumCrypto.identifier, **config)
    deploy_tx = dummy_contract.get_deploy_transaction(
        ledger_api, aea_ledger_ethereum.address
    )
    assert deploy_tx is not None and len(deploy_tx) == 7
    assert all(
        key in ["from", "value", "gas", "gasPrice", "nonce", "data", "chainId"]
        for key in deploy_tx.keys()
    )


def test_get_instance_no_address_cosmwasm(dummy_contract):
    """Tests get instance method with no address for fetchai."""
    ledger_api = ledger_apis_registry.make(
        FetchAICrypto.identifier,
        address=FETCHAI_DEFAULT_ADDRESS,
    )
    instance = dummy_contract.get_instance(ledger_api)
    assert instance is None


@pytest.mark.skipif(
    condition=(
        platform.system() == "Darwin"
        and sys.version_info.major == 3
        and sys.version_info.minor == 10
    ),
    reason="Fails because of cosmpy dependency on macOS/py310",
)
def test_get_deploy_transaction_cosmwasm(dummy_contract):
    """Tests the deploy transaction classmethod for fetchai."""
    aea_ledger_fetchai = crypto_registry.make(FetchAICrypto.identifier)
    ledger_api = ledger_apis_registry.make(
        FetchAICrypto.identifier,
        address=FETCHAI_DEFAULT_ADDRESS,
    )
    deploy_tx = dummy_contract.get_deploy_transaction(
        ledger_api, aea_ledger_fetchai.address, account_number=1, sequence=0
    )
    assert deploy_tx is not None and len(deploy_tx) == 2
    assert all(key in ["tx", "sign_data"] for key in deploy_tx.keys())


def test_scaffold():
    """Test the scaffold contract can be loaded/instantiated."""
    scaffold = MyScaffoldContract("config")
    kwargs = {"key": "value"}
    with pytest.raises(NotImplementedError):
        scaffold.get_raw_transaction("ledger_api", "contract_address", **kwargs)
    with pytest.raises(NotImplementedError):
        scaffold.get_raw_message("ledger_api", "contract_address", **kwargs)
    with pytest.raises(NotImplementedError):
        scaffold.get_state("ledger_api", "contract_address", **kwargs)


def test_scaffolded_contract_method_call():
    """Tests a contract method call."""

    @dataclass
    class AgentConfig:
        author = "dummy_author"
        contracts = ()
        agent_name = "dummy_agent"

    with tempfile.TemporaryDirectory() as temp_dir:
        packages_dir = Path(temp_dir, "packages")
        packages_dir.mkdir()
        PackageManagerV1(path=packages_dir).dump()

        ctx = Context(cwd=temp_dir, verbosity="DEBUG", registry_path=str(packages_dir))
        ctx.agent_config = AgentConfig()
        ctx.agent_config.directory = packages_dir / "dummy_author"
        ctx.config["to_local_registry"] = True

        contract_name = "i_uniswap_v2erc20"
        contract_abi_path = Path("tests", "test_contracts", "IUniswapV2ERC20.json")

        # Scaffold a new contract
        scaffold_item(ctx, CONTRACT, contract_name)
        add_contract_abi(ctx, contract_name, contract_abi_path)

        # Load the new contract
        contract_path = Path(packages_dir, "dummy_author", CONTRACTS, contract_name)
        contract = Contract.from_dir(str(contract_path))
        ledger_api = ledger_apis_registry.make(
            EthereumCrypto.identifier,
            address=ETHEREUM_DEFAULT_ADDRESS,
        )

        # Call a contract method: allowance
        SPENDER_ADDRESS = "0x7A1236d5195e31f1F573AD618b2b6FEFC85C5Ce6"
        OWNER_ADDRESS = "0x7A1236d5195e31f1F573AD618b2b6FEFC85C5Ce6"

        with mock.patch("web3.contract.contract.ContractFunction.call", return_value=0):
            res = contract.contract_method_call(
                ledger_api=ledger_api,
                method_name="allowance",
                owner=OWNER_ADDRESS,
                spender=SPENDER_ADDRESS,
            )

        assert res == 0


def test_contract_method_call():
    """Tests a contract method call."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    ledger_api = ledger_apis_registry.make(
        FetchAICrypto.identifier,
        address=FETCHAI_DEFAULT_ADDRESS,
    )
    with pytest.raises(NotImplementedError):
        contract.contract_method_call(ledger_api, "dummy_method")


def test_contract_method_call_2():
    """Tests a contract method call."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    ledger_api = MagicMock()
    ledger_api.contract_method_call.return_value = {}
    result = contract.contract_method_call(ledger_api, "dummy_method")
    assert result == {}


def test_build_transaction():
    """Tests a transaction build."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    ledger_api = ledger_apis_registry.make(
        FetchAICrypto.identifier,
        address=FETCHAI_DEFAULT_ADDRESS,
    )
    with pytest.raises(NotImplementedError):
        contract.build_transaction(ledger_api, "dummy_method", {}, {})


def test_build_transaction_2():
    """Tests a contract method call."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    ledger_api = MagicMock()
    ledger_api.build_transaction.return_value = {}
    result = contract.build_transaction(ledger_api, "dummy_method", {}, {})
    assert result == {}


def test_default_method_call():
    """Tests a default method build."""
    dummy_address = "0x0000000000000000000000000000000000000000"

    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )

    ledger_api = ledger_apis_registry.make(
        EthereumCrypto.identifier,
        address=ETHEREUM_DEFAULT_ADDRESS,
    )

    # Call a function present in the ABI but not in the contract package
    with mock.patch("web3.contract.contract.ContractFunction.call", return_value=0):
        result = contract.default_method_call(
            ledger_api=ledger_api,
            contract_address=dummy_address,
            method_name="getAddress",
            _addr=dummy_address,
        )

        assert result == 0


def test_get_transaction_transfer_logs():
    """Tests a transaction log retrieval."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    ledger_api = ledger_apis_registry.make(
        FetchAICrypto.identifier,
        address=FETCHAI_DEFAULT_ADDRESS,
    )
    with pytest.raises(NotImplementedError):
        contract.get_transaction_transfer_logs(ledger_api, "dummy_hash")


def test_get_transaction_transfer_logs_2():
    """Tests a transaction log retrieval."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    ledger_api = MagicMock()
    ledger_api.get_transaction_transfer_logs.return_value = {}
    contract.get_transaction_transfer_logs(ledger_api, "dummy_hash")


def test_get_method_data():
    """Tests get_method_data."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    dummy_address = "0x0000000000000000000000000000000000000000"

    contract_instance = MagicMock()
    method = MagicMock()
    method.abi = {
        "inputs": [{"name": "inputA"}, {"name": "inputB"}, {"name": "inputC"}]
    }
    contract_instance.get_function_by_name.return_value = method
    contract_instance.encode_abi.return_value = dummy_address
    ledger_api = MagicMock()
    ledger_api.get_contract_instance.return_value = contract_instance

    res = contract.get_method_data(
        ledger_api=ledger_api,
        contract_address=dummy_address,
        method_name="dummy_method_name",
        inputA=0,
        inputB=0,
        inputC=0,
    )
    assert res == {
        "data": b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    }


def test_get_method_data__key_error():
    """Tests get_method_data."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    dummy_address = "0x0000000000000000000000000000000000000000"

    contract_instance = MagicMock()
    method = MagicMock()
    method.abi = {
        "inputs": [{"name": "inputA"}, {"name": "inputB"}, {"name": "inputC"}]
    }
    contract_instance.get_function_by_name.return_value = method
    contract_instance.encode_abi.return_value = dummy_address
    ledger_api = MagicMock()
    ledger_api.get_contract_instance.return_value = contract_instance

    res = contract.get_method_data(
        ledger_api=ledger_api,
        contract_address=dummy_address,
        method_name="dummy_method_name",
        inputA=0,
        inputB=0,
        # missing inputC to provoke a KeyError exception
    )
    assert not res


def test_get_method_data__attribute_error():
    """Tests get_method_data."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    dummy_address = "0x0000000000000000000000000000000000000000"

    contract_instance = MagicMock()
    method = None  # provoke an attribute error when accessing method.abi
    contract_instance.get_function_by_name.return_value = method
    contract_instance.encode_abi.return_value = dummy_address
    ledger_api = MagicMock()
    ledger_api.get_contract_instance.return_value = contract_instance

    res = contract.get_method_data(
        ledger_api=ledger_api,
        contract_address=dummy_address,
        method_name="dummy_method_name",
    )
    assert not res


def test_get_method_data_type_error():
    """Tests get_method_data."""
    contract = Contract.from_dir(
        os.path.join(ROOT_DIR, "tests", "data", "dummy_contract")
    )
    dummy_address = "0x0000000000000000000000000000000000000000"

    def dummy_fun(abi_element_identifier, args):
        raise TypeError

    contract_instance = MagicMock()
    method = MagicMock()
    method.abi = {
        "inputs": [{"name": "inputA"}, {"name": "inputB"}, {"name": "inputC"}]
    }
    contract_instance.get_function_by_name.return_value = method
    contract_instance.encode_abi = dummy_fun
    ledger_api = MagicMock()
    ledger_api.get_contract_instance.return_value = contract_instance

    res = contract.get_method_data(
        ledger_api=ledger_api,
        contract_address=dummy_address,
        method_name="dummy_method_name",
        inputA=0,
        inputB=0,
        inputC=0,
    )
    assert not res
