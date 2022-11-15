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
"""Ethereum module wrapping the public and private key cryptography and ledger api."""
import decimal
import json
import logging
import math
import threading
import warnings
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union, cast
from uuid import uuid4
from ast import literal_eval

from aea.common import Address, JSONLike
from aea.crypto.base import Crypto, FaucetApi, Helper, LedgerApi
from aea.crypto.helpers import DecryptError, KeyIsIncorrect, hex_to_bytes_for_key
from aea.exceptions import enforce
from aea.helpers import http_requests as requests
from aea.helpers.base import try_decorator
from aea.helpers.io import open_file

from solana.publickey import PublicKey
from solana.rpc.api import Client
from solana.keypair import Keypair


from lru import LRU
from eth_keys import keys
import web3._utils.request
from web3 import HTTPProvider, Web3
from eth_account.signers.local import LocalAccount
from eth_account import Account


_default_logger = logging.getLogger(__name__)

_SOLANA = "solana"
TESTNET_NAME = "devnet"
DEFAULT_ADDRESS = "http://127.0.0.1:8899"
DEFAULT_CHAIN_ID = 1337
DEFAULT_CURRENCY_DENOM = "lamports"
_IDL = "idl"
_BYTECODE = "bytecode"


class SolanaCrypto(Crypto[Keypair]):
    """Class wrapping the Account Generation from Solana ledger."""

    identifier = _SOLANA

    def __init__(
        self,
        private_key_path: Optional[str] = None,
        password: Optional[str] = None,
        extra_entropy: Union[str, bytes, int] = "",
    ) -> None:
        """
        Instantiate an solana crypto object.

        :param private_key_path: the private key path of the agent
        :param password: the password to encrypt/decrypt the private key.
        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        """
        super().__init__(
            private_key_path=private_key_path,
            password=password,
            extra_entropy=extra_entropy,
        )
        bytes_representation = self.entity.secret_key
        self._public_key = self.entity.public_key
        self._address = self.entity.public_key

    @property
    def private_key(self) -> str:
        """
        Return a private key.

        64 random hex characters (i.e. 32 bytes) + "0x" prefix.

        :return: a private key string in hex format
        """
        return self.entity.key.secret_key.toBase58()

    @property
    def public_key(self) -> str:
        """
        Return a public key in hex format.

        128 hex characters (i.e. 64 bytes) + "0x" prefix.

        :return: a public key string in hex format
        """
        return self._public_key

    @property
    def address(self) -> str:
        """
        Return the address for the key pair.

        40 hex characters (i.e. 20 bytes) + "0x" prefix.

        :return: an address string in hex format
        """
        return self._address

    @classmethod
    def load_private_key_from_path(
        cls, file_name: str, password: Optional[str] = None
    ) -> Keypair:
        """
        Load a private key in base58 format from a file.

        :param file_name: the path to the hex file.
        :param password: the password to encrypt/decrypt the private key.
        :return: the Entity.
        """
        private_key = open(file_name, "r").read()

        try:
            l = literal_eval(private_key)
            key = Keypair.from_secret_key(l)
        except KeyIsIncorrect as e:

            raise KeyIsIncorrect(
                f"Error on key `{file_name}` load! : Error: {repr(e)} "
            ) from e

        return key

    def sign_message(self, message: bytes, is_deprecated_mode: bool = False) -> str:
        """
        Sign a message in bytes string form.

        :param message: the message to be signed
        :param is_deprecated_mode: if the deprecated signing is used
        :return: signature of the message in string form
        """
        if is_deprecated_mode and len(message) == 32:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                signature_dict = self.entity.signHash(message)
            signed_msg = signature_dict["signature"].hex()
        else:
            signable_message = encode_defunct(primitive=message)
            signature = self.entity.sign_message(signable_message=signable_message)
            signed_msg = signature["signature"].hex()
        return signed_msg

    def sign_transaction(self, transaction: JSONLike) -> JSONLike:
        """
        Sign a transaction in bytes string form.

        :param transaction: the transaction to be signed
        :return: signed transaction
        """
        signed_transaction = cast(Account, self.entity).sign_transaction(
            transaction_dict=transaction
        )
        signed_transaction_dict = SignedTransactionTranslator.to_dict(
            signed_transaction
        )
        return cast(JSONLike, signed_transaction_dict)

    @classmethod
    def generate_private_key(
        cls, extra_entropy: Union[str, bytes, int] = ""
    ) -> Keypair:
        """
        Generate a key pair for ethereum network.

        :param extra_entropy: add extra randomness to whatever randomness your OS can provide
        :return: account object
        """
        account = Keypair.generate()  # pylint: disable=no-value-for-parameter
        return account

    def encrypt(self, password: str) -> str:
        """
        Encrypt the private key and return in json.

        :param password: the password to decrypt.
        :return: json string containing encrypted private key.
        """
        encrypted = Account.encrypt(self.private_key, password)
        return json.dumps(encrypted)

    @classmethod
    def decrypt(cls, keyfile_json: str, password: str) -> str:
        """
        Decrypt the private key and return in raw form.

        :param keyfile_json: json str containing encrypted private key.
        :param password: the password to decrypt.
        :return: the raw private key (without leading "0x").
        """
        try:
            private_key = Account.decrypt(keyfile_json, password)
        except ValueError as e:
            if e.args[0] == "MAC mismatch":
                raise DecryptError() from e
            raise
        return private_key.hex()[2:]


class SolanaApi(LedgerApi):
    """Class to interact with the Solana Web3 APIs."""

    identifier = _SOLANA

    def __init__(self, **kwargs: Any):
        """
        Initialize the Ethereum ledger APIs.

        :param kwargs: keyword arguments
        """
        self._api = Web3(
            HTTPProvider(endpoint_uri=kwargs.pop("address", DEFAULT_ADDRESS))
        )
        self._chain_id = kwargs.pop("chain_id", DEFAULT_CHAIN_ID)
        self._is_gas_estimation_enabled = kwargs.pop("is_gas_estimation_enabled", False)

        self._default_gas_price_strategy: str = kwargs.pop(
            "default_gas_price_strategy", EIP1559
        )
        if self._default_gas_price_strategy not in AVAILABLE_STRATEGIES:
            raise ValueError(
                f"Gas price strategy must be one of {AVAILABLE_STRATEGIES}, provided: {self._default_gas_price_strategy}"
            )  # pragma: nocover

        self._gas_price_strategies: Dict[str, Dict] = kwargs.pop(
            "gas_price_strategies", DEFAULT_GAS_PRICE_STRATEGIES
        )

        self._poa_chain = kwargs.pop("poa_chain", False)
        if self._poa_chain:
            # https://web3py.readthedocs.io/en/stable/middleware.html#geth-style-proof-of-authority
            self._api.middleware_onion.inject(
                geth_poa_middleware, name="geth_poa_middleware", layer=0
            )
            _default_logger.info(
                "EthereumApi has been configured with Proof of Authority chain support"
            )

    @property
    def api(self) -> Web3:
        """Get the underlying API object."""
        return self._api

    def get_balance(
        self, address: Address, raise_on_try: bool = False
    ) -> Optional[int]:
        """Get the balance of a given account."""
        return self._try_get_balance(address, raise_on_try=raise_on_try)

    @try_decorator("Unable to retrieve balance: {}", logger_method="warning")
    def _try_get_balance(self, address: Address, **_kwargs: Any) -> Optional[int]:
        """Get the balance of a given account."""
        check_address = self._api.toChecksumAddress(address)
        return self._api.eth.get_balance(check_address)  # pylint: disable=no-member

    def get_state(
        self, callable_name: str, *args: Any, raise_on_try: bool = False, **kwargs: Any
    ) -> Optional[JSONLike]:
        """Call a specified function on the ledger API."""
        response = self._try_get_state(
            callable_name, *args, raise_on_try=raise_on_try, **kwargs
        )
        return response

    @try_decorator("Unable to get state: {}", logger_method="warning")
    def _try_get_state(  # pylint: disable=unused-argument
        self, callable_name: str, *args: Any, **kwargs: Any
    ) -> Optional[JSONLike]:
        """Try to call a function on the ledger API."""

        if "raise_on_try" in kwargs:
            logging.info(
                f"popping `raise_on_try` from {self.__class__.__name__}.get_state kwargs"
            )
            kwargs.pop("raise_on_try")

        function = getattr(self._api.eth, callable_name)
        response = function(*args, **kwargs)

        if isinstance(response, AttributeDict):
            result = AttributeDictTranslator.to_dict(response)
            return result

        if type(response) in (int, float, bytes, str, list, dict):  # pragma: nocover
            # missing full checks for nested objects
            return {f"{callable_name}_result": response}
        raise NotImplementedError(  # pragma: nocover
            f"Response must be of types=int, float, bytes, str, list, dict. Found={type(response)}."
        )

    def get_transfer_transaction(  # pylint: disable=arguments-differ
        self,
        sender_address: Address,
        destination_address: Address,
        amount: int,
        tx_fee: int,
        tx_nonce: str,
        chain_id: Optional[int] = None,
        max_fee_per_gas: Optional[int] = None,
        max_priority_fee_per_gas: Optional[str] = None,
        gas_price: Optional[str] = None,
        gas_price_strategy: Optional[str] = None,
        gas_price_strategy_extra_config: Optional[Dict] = None,
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """
        Submit a transfer transaction to the ledger.

        :param sender_address: the sender address of the payer.
        :param destination_address: the destination address of the payee.
        :param amount: the amount of wealth to be transferred (in Wei).
        :param tx_fee: the transaction fee (gas) to be used (in Wei).
        :param tx_nonce: verifies the authenticity of the tx.
        :param chain_id: the Chain ID of the Ethereum transaction.
        :param max_fee_per_gas: maximum amount you’re willing to pay, inclusive of `baseFeePerGas` and `maxPriorityFeePerGas`. The difference between `maxFeePerGas` and `baseFeePerGas + maxPriorityFeePerGas` is refunded  (in Wei).
        :param max_priority_fee_per_gas: the part of the fee that goes to the miner (in Wei).
        :param gas_price: the gas price (in Wei)
        :param gas_price_strategy: the gas price strategy to be used.
        :param gas_price_strategy_extra_config: extra config for gas price strategy.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: keyword arguments
        :return: the transfer transaction
        """
        transaction: Optional[JSONLike] = None
        chain_id = chain_id if chain_id is not None else self._chain_id
        destination_address = self._api.toChecksumAddress(destination_address)
        sender_address = self._api.toChecksumAddress(sender_address)
        nonce = self._try_get_transaction_count(
            sender_address,
            raise_on_try=raise_on_try,
        )
        if nonce is None:
            return transaction
        transaction = {
            "nonce": nonce,
            "chainId": chain_id,
            "to": destination_address,
            "value": amount,
            "gas": tx_fee,
            "data": tx_nonce,
        }
        if self._is_gas_estimation_enabled:
            transaction = self.update_with_gas_estimate(transaction)

        if max_fee_per_gas is not None:
            max_priority_fee_per_gas = (
                self._try_get_max_priority_fee(raise_on_try=raise_on_try)
                if max_priority_fee_per_gas is None
                else max_priority_fee_per_gas
            )
            transaction.update(
                {
                    "maxFeePerGas": max_fee_per_gas,
                    "maxPriorityFeePerGas": max_priority_fee_per_gas,
                }
            )

        if gas_price is not None:
            transaction.update({"gasPrice": gas_price})

        if gas_price is None and max_fee_per_gas is None:
            gas_pricing = self.try_get_gas_pricing(
                gas_price_strategy,
                gas_price_strategy_extra_config,
                raise_on_try=raise_on_try,
            )
            if gas_pricing is None:
                return transaction  # pragma: nocover
            transaction.update(gas_pricing)

        return transaction

    def _get_gas_price_strategy(
        self,
        gas_price_strategy: Optional[str] = None,
        extra_config: Optional[Dict] = None,
    ) -> Optional[Tuple[str, Callable]]:
        """
        Returns parameters for gas price callable.

        Note: The priority of gas price callable will be
        `extra_config(Runtime params) > self._gas_price_strategies (Set using config file.) > DEFAULT_GAS_PRICE_STRATEGIES (Default values.)`

        :param gas_price_strategy: name of the gas price strategy.
        :param extra_config: gas price strategy getter parameters.
        :return: gas price strategy's name and callable.
        """
        gas_price_strategy = (
            gas_price_strategy
            if gas_price_strategy is not None
            else self._default_gas_price_strategy
        )
        if gas_price_strategy not in AVAILABLE_STRATEGIES:  # pragma: nocover
            _default_logger.debug(
                f"Gas price strategy must be one of {AVAILABLE_STRATEGIES}, provided: {self._default_gas_price_strategy}"
            )
            return None

        _default_logger.debug(f"Using strategy: {gas_price_strategy}")
        gas_price_strategy_getter = self._gas_price_strategy_callables[
            gas_price_strategy
        ]

        parameters = cast(dict, DEFAULT_GAS_PRICE_STRATEGIES.get(gas_price_strategy))
        parameters.update(self._gas_price_strategies.get(gas_price_strategy, {}))
        parameters.update(extra_config or {})
        return gas_price_strategy, gas_price_strategy_getter(**parameters)

    @staticmethod
    def __reprice(old_price: Wei) -> Wei:
        return Wei(math.ceil(old_price * TIP_INCREASE))

    @try_decorator("Unable to retrieve gas price: {}", logger_method="warning")
    def try_get_gas_pricing(
        self,
        gas_price_strategy: Optional[str] = None,
        extra_config: Optional[Dict] = None,
        old_price: Optional[Dict[str, Wei]] = None,
        **_kwargs: Any,
    ) -> Optional[Dict[str, Wei]]:
        """
        Try get the gas price based on the provided strategy.

        :param gas_price_strategy: the gas price strategy to use, e.g., the EIP-1559 strategy.
            Can be either `eip1559` or `gas_station`.
        :param extra_config: gas price strategy getter parameters.
        :param old_price: the old gas price params in case that we are trying to resubmit a transaction.
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: a dictionary with the gas data.
        """

        retrieved_strategy = self._get_gas_price_strategy(
            gas_price_strategy,
            extra_config,
        )
        if retrieved_strategy is None:  # pragma: nocover
            return None
        gas_price_strategy, gas_price_strategy_callable = retrieved_strategy

        prior_strategy = self._api.eth.gasPriceStrategy
        try:
            self._api.eth.set_gas_price_strategy(gas_price_strategy_callable)
            gas_price = self._api.eth.generate_gas_price()
        finally:
            self._api.eth.set_gas_price_strategy(prior_strategy)  # pragma: nocover

        if gas_price is None or old_price is None:
            return gas_price

        gas_price = cast(Dict[str, Wei], gas_price)
        if gas_price_strategy in (EIP1559, EIP1559_POLYGON):
            updated_max_fee_per_gas = self.__reprice(old_price["maxFeePerGas"])
            updated_max_priority_fee_per_gas = self.__reprice(
                old_price["maxPriorityFeePerGas"]
            )

            if gas_price["maxFeePerGas"] < updated_max_fee_per_gas:
                gas_price["maxFeePerGas"] = updated_max_fee_per_gas
                gas_price["maxPriorityFeePerGas"] = updated_max_priority_fee_per_gas

        elif gas_price_strategy == GAS_STATION:
            updated_gas_price = self.__reprice(old_price["gasPrice"])
            gas_price["gasPrice"] = max(gas_price["gasPrice"], updated_gas_price)

        return gas_price

    @try_decorator("Unable to retrieve transaction count: {}", logger_method="warning")
    def _try_get_transaction_count(
        self, address: Address, **_kwargs: Any
    ) -> Optional[int]:
        """Try get the transaction count."""
        nonce = self._api.eth.get_transaction_count(  # pylint: disable=no-member
            self._api.toChecksumAddress(address)
        )
        return nonce

    def update_with_gas_estimate(self, transaction: JSONLike) -> JSONLike:
        """
        Attempts to update the transaction with a gas estimate

        :param transaction: the transaction
        :return: the updated transaction
        """
        gas_estimate = self._try_get_gas_estimate(transaction)
        if gas_estimate is not None:
            transaction["gas"] = gas_estimate
        return transaction

    @try_decorator("Unable to retrieve gas estimate: {}", logger_method="warning")
    def _try_get_gas_estimate(self, transaction: JSONLike) -> Optional[int]:
        """Try get the gas estimate."""
        gas_estimate: Optional[int] = None
        transaction = deepcopy(transaction)
        del transaction["gas"]
        try:
            gas_estimate = self._api.eth.estimate_gas(  # pylint: disable=no-member
                transaction=cast(
                    TxParams, AttributeDictTranslator.from_dict(transaction)
                )
            )
        except (ContractLogicError, ValueError) as e:
            _default_logger.warning(
                f"Unable to estimate gas with default state , "
                f"{type(e).__name__}: {e.__str__()}"
            )
            # gas estimation might fail when repricing txs
            # to avoid effects of pending txs when estimating gas
            # we can set the block identifier to "latest" block
            # this might fail if the node doesn't support the `block_identifier` param
            gas_estimate = self._api.eth.estimate_gas(  # pylint: disable=no-member
                transaction=cast(
                    TxParams, AttributeDictTranslator.from_dict(transaction)
                ),
                block_identifier=LatestBlockParam,
            )

        return gas_estimate

    def send_signed_transaction(
        self, tx_signed: JSONLike, raise_on_try: bool = False
    ) -> Optional[str]:
        """
        Send a signed transaction and wait for confirmation.

        :param tx_signed: the signed transaction
        :param raise_on_try: whether the method will raise or log on error
        :return: tx_digest, if present
        """
        tx_digest = self._try_send_signed_transaction(
            tx_signed, raise_on_try=raise_on_try
        )
        return tx_digest

    @try_decorator("Unable to send transaction: {}", logger_method="warning")
    def _try_send_signed_transaction(
        self, tx_signed: JSONLike, **_kwargs: Any
    ) -> Optional[str]:
        """
        Try send a signed transaction.

        :param tx_signed: the signed transaction
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: tx_digest, if present
        """
        signed_transaction = SignedTransactionTranslator.from_dict(tx_signed)
        hex_value = self._api.eth.send_raw_transaction(  # pylint: disable=no-member
            signed_transaction.rawTransaction
        )
        tx_digest = hex_value.hex()
        _default_logger.debug(
            "Successfully sent transaction with digest: {}".format(tx_digest)
        )
        return tx_digest

    def get_transaction_receipt(
        self, tx_digest: str, raise_on_try: bool = False
    ) -> Optional[JSONLike]:
        """
        Get the transaction receipt for a transaction digest.

        :param tx_digest: the digest associated to the transaction.
        :param raise_on_try: whether the method will raise or log on error
        :return: the tx receipt, if present
        """
        tx_receipt = self._try_get_transaction_receipt(
            tx_digest,
            raise_on_try=raise_on_try,
        )

        if tx_receipt is not None and not bool(tx_receipt["status"]):
            tx = self.get_transaction(tx_digest, raise_on_try=raise_on_try)
            tx_receipt["revert_reason"] = self._try_get_revert_reason(
                tx,
                raise_on_try=raise_on_try,
            )

        return tx_receipt

    @try_decorator(
        "Error when attempting getting tx receipt: {}", logger_method="debug"
    )
    def _try_get_transaction_receipt(
        self, tx_digest: str, **_kwargs: Any
    ) -> Optional[JSONLike]:
        """
        Try get the transaction receipt.

        :param tx_digest: the digest associated to the transaction.
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: the tx receipt, if present
        """
        tx_receipt = self._api.eth.get_transaction_receipt(  # pylint: disable=no-member
            cast(HexStr, tx_digest)
        )
        return AttributeDictTranslator.to_dict(tx_receipt)

    def get_transaction(
        self,
        tx_digest: str,
        raise_on_try: bool = False,
    ) -> Optional[JSONLike]:
        """
        Get the transaction for a transaction digest.

        :param tx_digest: the digest associated to the transaction.
        :param raise_on_try: whether the method will raise or log on error
        :return: the tx, if present
        """
        tx = self._try_get_transaction(tx_digest, raise_on_try=raise_on_try)
        return tx

    @try_decorator("Error when attempting getting tx: {}", logger_method="debug")
    def _try_get_transaction(
        self, tx_digest: str, **_kwargs: Any
    ) -> Optional[JSONLike]:
        """
        Get the transaction.

        :param tx_digest: the transaction digest.
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: the tx, if found
        """
        tx = self._api.eth.get_transaction(
            cast(HexStr, tx_digest)
        )  # pylint: disable=no-member
        return AttributeDictTranslator.to_dict(tx)

    @try_decorator(
        "Error when attempting getting tx revert reason: {}", logger_method="debug"
    )
    def _try_get_revert_reason(self, tx: TxData, **_kwargs: Any) -> str:
        """Try to check the revert reason of a transaction.

        :param tx: the transaction for which we want to get the revert reason.
        :param _kwargs: the keyword arguments. Possible kwargs are:
            `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
        :return: the revert reason message.
        """
        # build a new transaction to replay:
        replay_tx = {
            "to": tx["to"],
            "from": tx["from"],
            "value": tx["value"],
            "data": tx["input"],
        }

        try:
            # replay the transaction on the provider
            self.api.eth.call(replay_tx, tx["blockNumber"] - 1)
        except SolidityError as e:
            # execution reverted exception
            return str(e)
        except HTTPError as e:
            # http exception
            raise e
        else:
            # given tx not reverted
            raise ValueError(f"The given transaction has not been reverted!\ntx: {tx}")

    def get_contract_instance(
        self, contract_interface: Dict[str, str], contract_address: Optional[str] = None
    ) -> Any:
        """
        Get the instance of a contract.

        :param contract_interface: the contract interface.
        :param contract_address: the contract address.
        :return: the contract instance
        """
        if contract_address is None:
            instance = self.api.eth.contract(
                abi=contract_interface[_ABI],
                bytecode=contract_interface[_BYTECODE],
            )
        else:
            _contract_address = self.api.toChecksumAddress(contract_address)
            instance = self.api.eth.contract(
                address=_contract_address,
                abi=contract_interface[_ABI],
                bytecode=contract_interface[_BYTECODE],
            )
        return instance

    def get_deploy_transaction(  # pylint: disable=arguments-differ
        self,
        contract_interface: Dict[str, str],
        deployer_address: Address,
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """
        Get the transaction to deploy the smart contract.

        :param contract_interface: the contract interface.
        :param deployer_address: The address that will deploy the contract.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: keyword arguments
        :return: the transaction dictionary.
        """

        # value to send to contract (in Wei)
        value: int = kwargs.pop("value", 0)

        # the gas to be used (in Wei)
        gas: Optional[int] = kwargs.pop("gas", None)

        # maximum amount you’re willing to pay, inclusive of `baseFeePerGas` and
        # `maxPriorityFeePerGas`. The difference between `maxFeePerGas` and
        # `baseFeePerGas + maxPriorityFeePerGas` is refunded  (in Wei).
        max_fee_per_gas: Optional[int] = kwargs.pop("max_fee_per_gas", None)

        # the part of the fee that goes to the miner (in Wei).
        max_priority_fee_per_gas: Optional[str] = kwargs.pop(
            "max_priority_fee_per_gas", None
        )

        # the gas price (in Wei)
        gas_price: Optional[str] = kwargs.pop("gas_price", None)

        # the gas price strategy to be used.
        gas_price_strategy: Optional[str] = kwargs.pop("gas_price_strategy", None)

        # extra config for gas price strategy.
        gas_price_strategy_extra_config: Optional[Dict] = kwargs.pop(
            "gas_price_strategy_extra_config", None
        )

        transaction: Optional[JSONLike] = None
        _deployer_address = self.api.toChecksumAddress(deployer_address)
        nonce = self._try_get_transaction_count(
            _deployer_address, raise_on_try=raise_on_try
        )
        if nonce is None:
            return transaction
        instance = self.get_contract_instance(contract_interface)
        transaction = {
            "value": value,
            "nonce": nonce,
        }
        if max_fee_per_gas is not None:
            max_priority_fee_per_gas = (
                self._try_get_max_priority_fee(raise_on_try=raise_on_try)
                if max_priority_fee_per_gas is None
                else max_priority_fee_per_gas
            )
            if max_priority_fee_per_gas is None:
                return None  # pragma: nocover
            transaction.update(
                {
                    "maxFeePerGas": max_fee_per_gas,
                    "maxPriorityFeePerGas": max_priority_fee_per_gas,
                }
            )

        if gas_price is not None:
            transaction.update({"gasPrice": gas_price})

        if gas_price is None and max_fee_per_gas is None:
            gas_pricing = self.try_get_gas_pricing(
                gas_price_strategy,
                gas_price_strategy_extra_config,
                raise_on_try=raise_on_try,
            )

            if gas_pricing is None:
                return None  # pragma: nocover

            transaction.update(gas_pricing)

        transaction = instance.constructor(**kwargs).buildTransaction(transaction)

        if transaction is None:
            return None  # pragma: nocover
        transaction.pop("to", None)  # only 'from' address, don't insert 'to' address!
        transaction.update({"from": _deployer_address})
        if gas is not None:
            transaction.update({"gas": gas})
        if self._is_gas_estimation_enabled:
            transaction = self.update_with_gas_estimate(transaction)
        return transaction

    @try_decorator("Unable to retrieve max_priority_fee: {}", logger_method="warning")
    def _try_get_max_priority_fee(self, **_kwargs: Any) -> str:
        """Try get the gas estimate."""
        return cast(str, self.api.eth.max_priority_fee)

    @classmethod
    def is_valid_address(cls, address: Address) -> bool:
        """
        Check if the address is valid.

        :param address: the address to validate
        :return: whether the address is valid
        """
        return Web3.isAddress(address)

    @classmethod
    def contract_method_call(
        cls,
        contract_instance: Any,
        method_name: str,
        **method_args: Any,
    ) -> Optional[JSONLike]:
        """Call a contract's method

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract call parameters
        :return: the call result
        """
        method = getattr(contract_instance.functions, method_name)
        result = method(**method_args).call()
        return result

    def build_transaction(  # pylint: disable=too-many-arguments
        self,
        contract_instance: Any,
        method_name: str,
        method_args: Optional[Dict[Any, Any]],
        tx_args: Optional[Dict[Any, Any]],
        raise_on_try: bool = False,
    ) -> Optional[JSONLike]:
        """Prepare a transaction

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract parameters
        :param tx_args: the transaction parameters
        :param raise_on_try: whether the method will raise or log on error
        :return: the transaction
        """

        if method_args is None:
            raise ValueError("Argument 'method_args' cannot be 'None'.")

        method = getattr(contract_instance.functions, method_name)
        tx = method(**cast(Dict, method_args))

        if tx_args is None:
            raise ValueError("Argument 'tx_args' cannot be 'None'.")

        tx_args = cast(Dict, tx_args)

        nonce = self.api.eth.get_transaction_count(tx_args["sender_address"])
        tx_params = {
            "nonce": nonce,
            "value": tx_args["value"] if "value" in tx_args else 0,
            "gas": 1,  # set this as a placeholder to avoid estimation on buildTransaction()
        }

        # Parameter camel-casing due to contract api requirements
        for field in [
            "gas",
            "gasPrice",
            "maxFeePerGas",
            "maxPriorityFeePerGas",
        ]:
            if field in tx_args and tx_args[field] is not None:
                tx_params[field] = tx_args[field]

        if (
            "gasPrice" not in tx_params
            and "maxFeePerGas" not in tx_params
            and "maxPriorityFeePerGas" not in tx_params
        ):
            gas_data = self.try_get_gas_pricing(
                old_price=tx_args.get("old_price"), raise_on_try=raise_on_try
            )
            if gas_data:
                tx_params.update(gas_data)  # pragma: nocover

        tx = tx.buildTransaction(tx_params)
        if self._is_gas_estimation_enabled:
            tx = self.update_with_gas_estimate(tx)

        return tx

    def get_transaction_transfer_logs(  # pylint: disable=too-many-arguments,too-many-locals
        self,
        contract_instance: Any,
        tx_hash: str,
        target_address: Optional[str] = None,
    ) -> Optional[JSONLike]:
        """
        Get all transfer events derived from a transaction.

        :param contract_instance: the contract
        :param tx_hash: the transaction hash
        :param target_address: optional address to filter tranfer events to just those that affect it
        :return: the transfer logs
        """
        try:
            tx_receipt = self.api.eth.get_transaction_receipt(tx_hash)
            if tx_receipt is None:
                raise ValueError  # pragma: nocover

        except (TransactionNotFound, ValueError):  # pragma: nocover
            return dict(logs=[])

        transfer_logs = contract_instance.events.Transfer().processReceipt(tx_receipt)

        return dict(logs=transfer_logs)


class SolanaFaucetApi(FaucetApi):
    """Solana testnet faucet API."""

    identifier = _SOLANA
    testnet_name = TESTNET_NAME

    def get_wealth(self, address: Address, url: Optional[str] = None) -> None:
        """
        Get wealth from the faucet for the provided address.

        :param address: the address.
        :param url: the url
        """
        self._try_get_wealth(address, url)

    @staticmethod
    @try_decorator(
        "An error occured while attempting to generate wealth:\n{}",
        logger_method="error",
    )
    def _try_get_wealth(address: Address, url: Optional[str] = None) -> None:
        """
        Get wealth from the faucet for the provided address.

        :param address: the address.
        :param url: the url
        """
        if url is None:
            raise ValueError(  # pragma: nocover
                "Url is none, no default url provided. Please provide a faucet url."
            )
        solana_client = Client(url)
        response = None
        try:
            response = solana_client.request_airdrop(PublicKey(address), 1000000000)
        except Exception as e:
            pass

        if response == None:
            _default_logger.error("Response: {}".format("airdrop failed"))
        elif "error" in response:  # pragma: no cover
            _default_logger.error("Response: {}".format("airdrop failed"))
        elif "result" in response:  # pragma: nocover

            _default_logger.warning(
                "Response: {}\nMessage: {}".format(
                    "success", response['result']
                )
            )


class LruLockWrapper:
    """Wrapper for LRU with threading.Lock."""

    def __init__(self, lru: LRU) -> None:
        """Init wrapper."""
        self.lru = lru
        self.lock = threading.Lock()

    def __getitem__(self, *args: Any, **kwargs: Any) -> Any:
        """Get item"""
        with self.lock:
            return self.lru.__getitem__(*args, **kwargs)

    def __setitem__(self, *args: Any, **kwargs: Any) -> Any:
        """Set item."""
        with self.lock:
            return self.lru.__setitem__(*args, **kwargs)

    def __contains__(self, *args: Any, **kwargs: Any) -> Any:
        """Contain item."""
        with self.lock:
            return self.lru.__contains__(*args, **kwargs)

    def __delitem__(self, *args: Any, **kwargs: Any) -> Any:
        """Del item."""
        with self.lock:
            return self.lru.__delitem__(*args, **kwargs)


def set_wrapper_for_web3py_session_cache() -> None:
    """Wrap web3py session cache with threading.Lock."""

    # pylint: disable=protected-access
    web3._utils.request._session_cache = LruLockWrapper(
        web3._utils.request._session_cache
    )


set_wrapper_for_web3py_session_cache()
