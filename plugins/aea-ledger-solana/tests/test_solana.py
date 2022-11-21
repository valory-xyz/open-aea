# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2021-2022 Valory AG
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
"""This module contains the tests of the ethereum module."""

import hashlib
import logging
import math
import random
import re
import tempfile
import time
from pathlib import Path
from typing import Dict, Generator, Optional, Tuple, Union, cast
from unittest import mock
from unittest.mock import MagicMock, patch

import pytest
from aea_ledger_solana import (
    SolanaApi,
    SolanaCrypto,
    SolanaFaucetApi,
    LruLockWrapper,
    # requests,
)
from solana.transaction import Transaction

# from web3 import Web3
from web3._utils.request import _session_cache as session_cache

from aea.common import JSONLike
from aea.crypto.helpers import DecryptError, KeyIsIncorrect

from tests.conftest import DEFAULT_GANACHE_CHAIN_ID, MAX_FLAKY_RERUNS, ROOT_DIR


# def get_history_data(n_blocks: int, base_multiplier: int = 100) -> Dict:
#     """Returns dummy blockchain history data."""

#     return {
#         "oldestBlock": 1,
#         "reward": [
#             [math.ceil(random.random() * base_multiplier) * 1e1]
#             for _ in range(n_blocks)
#         ],
#         "baseFeePerGas": [
#             math.ceil(random.random() * base_multiplier) * 1e9 for _ in range(n_blocks)
#         ],
#     }


# def test_creation(ethereum_private_key_file):
#     """Test the creation of the crypto_objects."""
#     assert EthereumCrypto(), "Managed to initialise the eth_account"
#     assert EthereumCrypto(
#         ethereum_private_key_file
#     ), "Managed to load the eth private key"


# def test_initialization():
#     """Test the initialisation of the variables."""
#     account = EthereumCrypto()
#     assert account.entity is not None, "The property must return the account."
#     assert (
#         account.address is not None and type(account.address) == str
#     ), "After creation the display address must not be None"
#     assert (
#         account.public_key is not None and type(account.public_key) == str
#     ), "After creation the public key must no be None"
#     assert account.entity is not None, "After creation the entity must no be None"


def test_derive_address():
    """Test the get_address_from_public_key method"""
    account = SolanaCrypto()
    address = SolanaApi.get_address_from_public_key(account.public_key)
    assert account.address == address, "Address derivation incorrect"


def test_sign_and_recover_message():
    """Test the signing and the recovery function for the sol_crypto."""
    account = SolanaCrypto()
    sign_bytes = account.sign_message(message=b"hello")
    assert len(sign_bytes) > 0, "The len(signature) must not be 0"
    # recovered_addresses = SolanaApi.recover_message(
    #     message=b"hello", signature=sign_bytes
    # )
    # assert len(recovered_addresses) == 1, "Wrong number of addresses recovered."
    # assert (
    #     recovered_addresses[0] == account.address
    # ), "Failed to recover the correct address."


# def test_sign_and_recover_message_public_key(ethereum_private_key_file):
#     """Test the signing and the recovery function for the eth_crypto."""
#     account = EthereumCrypto(ethereum_private_key_file)
#     sign_bytes = account.sign_message(message=b"hello")
#     assert len(sign_bytes) > 0, "The len(signature) must not be 0"
#     recovered_public_keys = EthereumApi.recover_public_keys_from_message(
#         message=b"hello", signature=sign_bytes
#     )
#     assert len(recovered_public_keys) == 1, "Wrong number of public keys recovered."
#     assert (
#         EthereumApi.get_address_from_public_key(recovered_public_keys[0])
#         == account.address
#     ), "Failed to recover the correct address."


def test_get_hash():
    """Test the get hash functionality."""
    expected_hash = "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
    hash_ = SolanaApi.get_hash(message=b"hello")
    assert expected_hash == hash_


# def test_dump_positive(ethereum_private_key_file):
#     """Test dump."""
#     account = EthereumCrypto(ethereum_private_key_file)
#     account.dump(MagicMock())


# def test_api_creation(ethereum_testnet_config):
#     """Test api instantiation."""
#     assert EthereumApi(**ethereum_testnet_config), "Failed to initialise the api"


# def test_api_none(ethereum_testnet_config):
#     """Test the "api" of the cryptoApi is none."""
#     eth_api = EthereumApi(**ethereum_testnet_config)
#     assert eth_api.api is not None, "The api property is None."


# def test_validate_address():
#     """Test the is_valid_address functionality."""
#     account = EthereumCrypto()
#     assert EthereumApi.is_valid_address(account.address)
#     assert not EthereumApi.is_valid_address(account.address + "wrong")


# @pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
# @pytest.mark.integration
# @pytest.mark.ledger
# def test_get_balance(ethereum_testnet_config, ganache, ethereum_private_key_file):
#     """Test the balance is zero for a new account."""
#     ethereum_api = EthereumApi(**ethereum_testnet_config)
#     ec = EthereumCrypto()
#     balance = ethereum_api.get_balance(ec.address)
#     assert balance == 0, "New account has a positive balance."
#     ec = EthereumCrypto(private_key_path=ethereum_private_key_file)
#     balance = ethereum_api.get_balance(ec.address)
#     assert balance > 0, "Existing account has no balance."


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_load_contract_interface_pid():
    """Test that you can load contract interface from onchain idl store."""
    solana_api = SolanaApi()
    contract_interface = solana_api.load_contract_interface(
        program_address="ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD", rpc_api="https://api.mainnet-beta.solana.com")

    assert "name" in contract_interface, "idl has a name"


def _wait_get_receipt(
    solana_api: SolanaApi, transaction_digest: str
) -> Tuple[Optional[JSONLike], bool]:
    transaction_receipt = None
    not_settled = True
    elapsed_time = 0
    time_to_wait = 40
    sleep_time = 2
    while not_settled and elapsed_time < time_to_wait:
        elapsed_time += sleep_time
        time.sleep(sleep_time)
        transaction_receipt = solana_api.get_transaction_receipt(transaction_digest)
        if transaction_receipt['result'] is None:
            continue
        is_settled = solana_api.is_transaction_settled(transaction_receipt)
        not_settled = not is_settled

    return transaction_receipt, not not_settled


def _construct_and_settle_tx(
    solana_api: SolanaApi,
    account: SolanaCrypto,
    tx_params: dict,
) -> Tuple[str, JSONLike, bool]:
    """Construct and settle a transaction."""
    transfer_transaction = solana_api.get_transfer_transaction(**tx_params)
    assert (
        isinstance(transfer_transaction, Transaction)
    ), "Incorrect transfer_transaction constructed."

    signed_transaction = account.sign_transaction(
        transfer_transaction, solana_api.generate_tx_nonce(solana_api)
    )
    assert (
        isinstance(signed_transaction, Transaction)
    ), "Incorrect signed_transaction constructed."

    transaction_digest = solana_api.send_signed_transaction(signed_transaction)
    assert transaction_digest is not None, "Failed to submit transfer transaction!"

    transaction_receipt, is_settled = _wait_get_receipt(
        solana_api, transaction_digest
    )

    assert transaction_receipt['result'] is not None, "Failed to retrieve transaction receipt."

    return transaction_digest, transaction_receipt, is_settled


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_construct_sign_and_submit_transfer_transaction():
    """Test the construction, signing and submitting of a transfer transaction."""
    account1 = SolanaCrypto(private_key_path="./solana_private_key.txt")
    account2 = SolanaCrypto()

    solana_api = SolanaApi()
    solana_faucet_api = SolanaFaucetApi()

    solana_faucet_api.get_wealth(account2.address)

    time.sleep(10)
    balance1 = solana_api.get_balance(account1.address)
    balance2 = solana_api.get_balance(account2.address)
    counter = 0
    flag = True
    while flag == True:
        balance2 = solana_api.get_balance(account2.address)
        if balance2 != 0:
            flag = False
        counter += 1
        if counter > 10:
            flag = False
        time.sleep(2)

    AMOUNT = 232323
    tx_params = {
        "sender_address": account1.address,
        "destination_address": account2.address,
        "amount": AMOUNT,
    }

    transaction_digest, transaction_receipt, is_settled = _construct_and_settle_tx(
        solana_api,
        account1,
        tx_params,
    )
    assert is_settled, "Failed to verify tx!"

    tx = solana_api.get_transaction(transaction_digest)

    assert tx['result'] == transaction_receipt['result'], "Should be same"

    balance3 = solana_api.get_balance(account2.address)

    assert balance2 + AMOUNT == balance3, "Should be the same balance"


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_sol_balance(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        # solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(private_key_path="./solana_private_key.txt")
        sa = SolanaApi()

        balance = sa.get_balance(sc.address)
        assert isinstance(balance, int)


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_tx(caplog):
    """Test get tx from signature"""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        sc = SolanaCrypto(private_key_path="./solana_private_key.txt")
        solana_api = SolanaApi()
        tx_signature = solana_faucet_api.get_wealth(
            sc.address, "http://127.0.0.1:8899/")

        tx, settled = _wait_get_receipt(solana_api, tx_signature)
        assert settled is True


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_wealth(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        # sc = SolanaCrypto(private_key_path="./solana_private_key.txt")
        sc = SolanaCrypto()

        tx_signature = solana_faucet_api.get_wealth(
            sc.address, "http://127.0.0.1:8899/")

        assert tx_signature is not None


@pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
@pytest.mark.integration
@pytest.mark.ledger
def test_get_wealth_positive(caplog):
    """Test the balance is zero for a new account."""
    with caplog.at_level(logging.DEBUG, logger="aea.crypto.solana._default_logger"):
        solana_faucet_api = SolanaFaucetApi()
        # sc = SolanaCrypto(private_key_path="./solana_private_key.txt")
        sc = SolanaCrypto()

        tx_signature = solana_faucet_api.get_wealth(
            sc.address, "test")

        assert (
            "airdrop failed" in caplog.text
        ), f"Cannot find message in output: {caplog.text}"


# @pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
# @pytest.mark.integration
# @pytest.mark.ledger
# def test_get_deploy_transaction(ethereum_testnet_config, ganache):
#     """Test the get deploy transaction method."""
#     ethereum_api = EthereumApi(**ethereum_testnet_config)
#     ec2 = EthereumCrypto()
#     interface = {"abi": [], "bytecode": b""}
#     max_priority_fee_per_gas = 1000000000
#     max_fee_per_gas = 1000000000
#     deploy_tx = ethereum_api.get_deploy_transaction(
#         contract_interface=interface,
#         deployer_address=ec2.address,
#         value=0,
#         max_priority_fee_per_gas=max_priority_fee_per_gas,
#         max_fee_per_gas=max_fee_per_gas,
#     )
#     assert type(deploy_tx) == dict and len(deploy_tx) == 8
#     assert all(
#         key
#         in [
#             "from",
#             "value",
#             "gas",
#             "nonce",
#             "data",
#             "maxPriorityFeePerGas",
#             "maxFeePerGas",
#             "chainId",
#         ]
#         for key in deploy_tx.keys()
#     )


def test_load_contract_interface():
    """Test the load_contract_interface method."""
    path = Path(ROOT_DIR, "tests", "data", "dummy_contract", "build", "idl.json")
    result = SolanaApi.load_contract_interface(path)

    assert "name" in result


def test_load_contract_instance():
    """Test the load_contract_interface method."""
    path = Path(ROOT_DIR, "tests", "data", "dummy_contract", "build", "idl.json")
    result = SolanaApi.load_contract_interface(path)
    pid = "ZETAxsqBRek56DhiGXrn75yj2NHU3aYUnxvHXpkf3aD"
    instance = SolanaApi.get_contract_instance(SolanaApi,
                                               contract_interface=result, contract_address=pid)

    assert hasattr(instance, 'coder')


# @patch.object(EthereumApi, "_try_get_transaction_count", return_value=None)
# def test_ethereum_api_get_transfer_transaction(*args):
#     """Test EthereumApi.get_transfer_transaction."""
#     ec1 = EthereumCrypto()
#     ec2 = EthereumCrypto()
#     ethereum_api = EthereumApi(**get_default_gas_strategies())
#     args = {
#         "sender_address": ec1.address,
#         "destination_address": ec2.address,
#         "amount": 1,
#         "tx_fee": 0,
#         "tx_nonce": "",
#         "max_fee_per_gas": 20,
#     }
#     assert ethereum_api.get_transfer_transaction(**args) is None


# @patch.object(EthereumApi, "_try_get_transaction_count", return_value=1)
# @patch.object(EthereumApi, "_try_get_max_priority_fee", return_value=1)
# def test_ethereum_api_get_transfer_transaction_2(*args):
#     """Test EthereumApi.get_transfer_transaction."""
#     ec1 = EthereumCrypto()
#     ec2 = EthereumCrypto()
#     ethereum_api = EthereumApi(**get_default_gas_strategies())
#     ethereum_api._is_gas_estimation_enabled = True
#     args = {
#         "sender_address": ec1.address,
#         "destination_address": ec2.address,
#         "amount": 1,
#         "tx_fee": 0,
#         "tx_nonce": "",
#         "max_fee_per_gas": 10,
#     }
#     with patch.object(ethereum_api.api.eth, "estimate_gas", return_value=1):
#         assert len(ethereum_api.get_transfer_transaction(**args)) == 8


# @patch.object(EthereumApi, "_try_get_transaction_count", return_value=1)
# def test_ethereum_api_get_transfer_transaction_3(*args):
#     """Test EthereumApi.get_transfer_transaction."""
#     ec1 = EthereumCrypto()
#     ec2 = EthereumCrypto()
#     ethereum_api = EthereumApi(**get_default_gas_strategies())
#     ethereum_api._is_gas_estimation_enabled = True
#     args = {
#         "sender_address": ec1.address,
#         "destination_address": ec2.address,
#         "amount": 1,
#         "tx_fee": 0,
#         "tx_nonce": "",
#         "max_fee_per_gas": 10,
#     }
#     with patch.object(ethereum_api.api.eth, "_max_priority_fee", return_value=1):
#         assert len(ethereum_api.get_transfer_transaction(**args)) == 8


# def test_ethereum_api_get_deploy_transaction(ethereum_testnet_config):
#     """Test EthereumApi.get_deploy_transaction."""
#     ethereum_api = EthereumApi(**ethereum_testnet_config)
#     ec1 = EthereumCrypto()
#     with patch.object(ethereum_api.api.eth, "get_transaction_count", return_value=None):
#         assert (
#             ethereum_api.get_deploy_transaction(
#                 **{
#                     "contract_interface": {"": ""},
#                     "deployer_address": ec1.address,
#                     "value": 1,
#                     "max_fee_per_gas": 10,
#                 }
#             )
#             is None
#         )


def test_session_cache():
    """Test session cache."""
    assert isinstance(session_cache, LruLockWrapper)

    session_cache[1] = 1
    assert session_cache[1] == 1
    del session_cache[1]
    assert 1 not in session_cache


# def test_dump_load_with_password():
#     """Test dumping and loading a key with password."""
#     with tempfile.TemporaryDirectory() as dirname:
#         encrypted_file_name = Path(dirname, "eth_key_encrypted")
#         password = "somePwd"  # nosec
#         ec = EthereumCrypto()
#         ec.dump(encrypted_file_name, password)
#         assert encrypted_file_name.exists()
#         with pytest.raises(DecryptError, match="Decrypt error! Bad password?"):
#             ec2 = EthereumCrypto.load_private_key_from_path(
#                 encrypted_file_name, "wrongPassw"
#             )
#         ec2 = EthereumCrypto(encrypted_file_name, password)
#         assert ec2.private_key == ec.private_key


# def test_load_errors():
#     """Test load errors: bad password, no password specified."""
#     ec = EthereumCrypto()
#     with patch.object(EthereumCrypto, "load", return_value="bad sTring"):
#         with pytest.raises(KeyIsIncorrect, match="Try to specify `password`"):
#             ec.load_private_key_from_path("any path")

#         with pytest.raises(KeyIsIncorrect, match="Wrong password?"):
#             ec.load_private_key_from_path("any path", password="some")


# def test_decrypt_error():
#     """Test bad password error on decrypt."""
#     ec = EthereumCrypto()
#     ec._pritvate_key = EthereumCrypto.generate_private_key()
#     password = "test"
#     encrypted_data = ec.encrypt(password=password)
#     with pytest.raises(DecryptError, match="Bad password"):
#         ec.decrypt(encrypted_data, password + "some")

#     with patch(
#         "aea_ledger_ethereum.ethereum.Account.decrypt",
#         side_effect=ValueError("expected"),
#     ):
#         with pytest.raises(ValueError, match="expected"):
#             ec.decrypt(encrypted_data, password + "some")


# def test_helper_get_contract_address():
#     """Test EthereumHelper.get_contract_address."""
#     assert EthereumHelper.get_contract_address({"contractAddress": "123"}) == "123"


# def test_contract_method_call():
#     """Test EthereumApi.contract_method_call."""

#     method_mock = MagicMock()
#     method_mock().call = MagicMock(return_value={"value": 0})

#     contract_instance = MagicMock()
#     contract_instance.functions.dummy_method = method_mock

#     result = EthereumApi.contract_method_call(
#         contract_instance=contract_instance, method_name="dummy_method", dummy_arg=1
#     )
#     assert result["value"] == 0


# def test_build_transaction(ethereum_testnet_config):
#     """Test EthereumApi.build_transaction."""

#     def pass_tx_params(tx_params):
#         return tx_params

#     tx_mock = MagicMock()
#     tx_mock.buildTransaction = pass_tx_params

#     method_mock = MagicMock(return_value=tx_mock)

#     contract_instance = MagicMock()
#     contract_instance.functions.dummy_method = method_mock

#     eth_api = EthereumApi(**ethereum_testnet_config)

#     with pytest.raises(
#         ValueError, match=re.escape("Argument 'method_args' cannot be 'None'.")
#     ):
#         eth_api.build_transaction(
#             contract_instance=contract_instance,
#             method_name="dummy_method",
#             method_args=None,
#             tx_args={},
#         )
#     with pytest.raises(
#         ValueError, match=re.escape("Argument 'tx_args' cannot be 'None'.")
#     ):
#         eth_api.build_transaction(
#             contract_instance=contract_instance,
#             method_name="dummy_method",
#             method_args={},
#             tx_args=None,
#         )

#     with mock.patch(
#         "web3.eth.Eth.get_transaction_count",
#         return_value=0,
#     ):
#         result = eth_api.build_transaction(
#             contract_instance=contract_instance,
#             method_name="dummy_method",
#             method_args={},
#             tx_args=dict(
#                 sender_address="sender_address",
#                 eth_value=0,
#                 gas=0,
#                 gasPrice=0,  # camel-casing due to contract api requirements
#                 maxFeePerGas=0,  # camel-casing due to contract api requirements
#                 maxPriorityFeePerGas=0,  # camel-casing due to contract api requirements
#             ),
#         )

#         assert result == dict(
#             nonce=0,
#             value=0,
#             gas=0,
#             gasPrice=0,
#             maxFeePerGas=0,
#             maxPriorityFeePerGas=0,
#         )

#         with mock.patch.object(
#             EthereumApi,
#             "try_get_gas_pricing",
#             return_value={"gas": 0},
#         ):
#             result = eth_api.build_transaction(
#                 contract_instance=contract_instance,
#                 method_name="dummy_method",
#                 method_args={},
#                 tx_args=dict(
#                     sender_address="sender_address",
#                     eth_value=0,
#                 ),
#             )

#             assert result == dict(nonce=0, value=0, gas=0)


# def test_get_transaction_transfer_logs(ethereum_testnet_config):
#     """Test EthereumApi.get_transaction_transfer_logs."""
#     eth_api = EthereumApi(**ethereum_testnet_config)

#     dummy_receipt = {"logs": [{"topics": ["0x0", "0x0"]}]}

#     with mock.patch(
#         "web3.eth.Eth.get_transaction_receipt",
#         return_value=dummy_receipt,
#     ):
#         contract_instance = MagicMock()
#         contract_instance.events.Transfer().processReceipt.return_value = {"log": "log"}

#         result = eth_api.get_transaction_transfer_logs(
#             contract_instance=contract_instance,
#             tx_hash="dummy_hash",
#         )

#         assert result == dict(logs={"log": "log"})


# def test_get_transaction_transfer_logs_raise(ethereum_testnet_config):
#     """Test EthereumApi.get_transaction_transfer_logs."""
#     eth_api = EthereumApi(**ethereum_testnet_config)

#     with mock.patch(
#         "web3.eth.Eth.get_transaction_receipt",
#         return_value=None,
#     ):
#         contract_instance = MagicMock()
#         contract_instance.events.Transfer().processReceipt.return_value = {"log": "log"}

#         result = eth_api.get_transaction_transfer_logs(
#             contract_instance=contract_instance,
#             tx_hash="dummy_hash",
#         )

#         assert result == dict(logs=[])


# @pytest.mark.flaky(reruns=MAX_FLAKY_RERUNS)
# @pytest.mark.integration
# @pytest.mark.ledger
# def test_revert_reason(
#     ethereum_private_key_file: str,
#     ethereum_testnet_config: dict,
#     ganache: Generator,
# ) -> None:
#     """Test the retrieval of the revert reason for a transaction."""
#     account = EthereumCrypto(private_key_path=ethereum_private_key_file)
#     ec2 = EthereumCrypto()
#     ethereum_api = EthereumApi(**ethereum_testnet_config)

#     tx_params = {
#         "sender_address": account.address,
#         "destination_address": ec2.address,
#         "amount": 40000,
#         "tx_fee": 30000,
#         "tx_nonce": 0,
#         "chain_id": DEFAULT_GANACHE_CHAIN_ID,
#         "max_priority_fee_per_gas": 1_000_000_000,
#         "max_fee_per_gas": 1_000_000_000,
#     }

#     with mock.patch(
#         "web3.eth.Eth.get_transaction_receipt",
#         return_value=AttributeDict({"status": 0}),
#     ):
#         with mock.patch(
#             "web3.eth.Eth.call",
#             side_effect=SolidityError("test revert reason"),
#         ):
#             _, transaction_receipt, is_settled = _construct_and_settle_tx(
#                 ethereum_api,
#                 account,
#                 tx_params,
#             )

#             assert transaction_receipt["revert_reason"] == "test revert reason"
