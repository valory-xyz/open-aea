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
import zlib


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
from nacl.signing import VerifyKey
from pathlib import Path
import asyncio
import json
from solana.blockhash import Blockhash
from solana.publickey import PublicKey
from anchorpy import Program, Provider
from anchorpy.idl import Idl, _decode_idl_account, _idl_address
from anchorpy.coder.accounts import ACCOUNT_DISCRIMINATOR_SIZE

from solana.system_program import TransferParams, transfer
from solana.transaction import Transaction
from base64 import b64decode

from lru import LRU
from eth_keys import keys
import web3._utils.request
from web3 import HTTPProvider, Web3
from eth_account.signers.local import LocalAccount
from eth_account import Account


_default_logger = logging.getLogger(__name__)

_SOLANA = "solana"
TESTNET_NAME = "testnet"
DEFAULT_ADDRESS = "http://127.0.0.1:8899"
DEFAULT_CHAIN_ID = "solana"
DEFAULT_CURRENCY_DENOM = "lamports"
_IDL = "idl"
_BYTECODE = "bytecode"


def _pako_inflate(data):
    # https://stackoverflow.com/questions/46351275/using-pako-deflate-with-python
    decompress = zlib.decompressobj(15)
    decompressed_data = decompress.decompress(data)
    decompressed_data += decompress.flush()
    return decompressed_data


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

        64 random hex characters (i.e. 32 bytes) prefix.

        :return: a private key string in hex format
        """

        return self.entity.secret_key.hex()

    @property
    def public_key(self) -> str:
        """
        Return a public key in hex format.


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

        keypair = Keypair.from_secret_key(bytes.fromhex(self.private_key))
        signed_msg = keypair.sign(message)

        return signed_msg

    def sign_transaction(self, transaction: JSONLike, recent_blockhash: Blockhash) -> JSONLike:
        """
        Sign a transaction in bytes string form.

        :param transaction: the transaction to be signed
        :param recent_blockhash: a recent blockhash
        :return: signed transaction
        """

        keypair = Keypair.from_secret_key(bytes.fromhex(self.private_key))
        transaction.recent_blockhash = recent_blockhash
        transaction.sign(keypair)

        return transaction

    @ classmethod
    def generate_private_key(
        cls, extra_entropy: Union[str, bytes, int] = ""
    ) -> Keypair:
        """
        Generate a key pair for Solana network.

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

    @ classmethod
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
        Initialize the Solana ledger APIs.

        :param kwargs: keyword arguments
        """
        self._api = Client(
            endpoint=kwargs.pop("address", DEFAULT_ADDRESS)
        )
        self._chain_id = kwargs.pop("chain_id", DEFAULT_CHAIN_ID)

    @property
    def api(self) -> Web3:
        """Get the underlying API object."""
        return self._api

    @property
    def recent_blockhash(self) -> str:
        """
        Return a recent blockhash.


        :return: a blockhash
        """
        result = self._api.get_recent_blockhash()
        blockhash = result['result']['value']['blockhash']

        return Blockhash(blockhash)

    def update_with_gas_estimate(self, transaction: JSONLike) -> JSONLike:
        """
        **DO NOT NEED**
        Attempts to update the transaction with a gas estimate

        :param transaction: the transaction
        :return: the updated transaction
        """
        # gas_estimate = self._try_get_gas_estimate(transaction)
        # if gas_estimate is not None:
        #     transaction["gas"] = gas_estimate
        return transaction

    def get_balance(
        self, address: Address, raise_on_try: bool = False
    ) -> Optional[int]:
        """Get the balance of a given account."""
        return self._try_get_balance(address, raise_on_try=raise_on_try)

    @try_decorator("Unable to retrieve balance: {}", logger_method="warning")
    def _try_get_balance(self, address: Address, **_kwargs: Any) -> Optional[int]:
        """Get the balance of a given account."""
        response = self._api.get_balance(address)  # pylint: disable=no-member
        return response['result']['value']

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

        # if isinstance(response, AttributeDict):
        #     result = AttributeDictTranslator.to_dict(response)
        #     return result

        # if type(response) in (int, float, bytes, str, list, dict):  # pragma: nocover
        #     # missing full checks for nested objects
        #     return {f"{callable_name}_result": response}
        raise NotImplementedError(  # pragma: nocover
            f"Response must be of types=int, float, bytes, str, list, dict. Found={type(response)}."
        )

    @classmethod
    def recover_message(
        cls, message: bytes, signature: str, is_deprecated_mode: bool = False
    ) -> Tuple[Address, ...]:
        """
        **TO BE DONE**
        Recover the addresses from the hash.

        :param message: the message we expect
        :param signature: the transaction signature
        :param is_deprecated_mode: if the deprecated signing was used
        :return: the recovered addresses
        """

        try:
            pass
            # VerifyKey(bytes(self.address)).verify(msg.message, msg.signature)
        except:
            return False
        return True
        return "(address,)"

    @classmethod
    def recover_public_keys_from_message(
        cls, message: bytes, signature: str, is_deprecated_mode: bool = False
    ) -> Tuple[str, ...]:
        """
        **TO BE DONE**
        Get the public key used to produce the `signature` of the `message`

        :param message: raw bytes used to produce signature
        :param signature: signature of the message
        :param is_deprecated_mode: if the deprecated signing was used
        :return: the recovered public keys
        """
        # if not is_deprecated_mode:
        #     signable_message = encode_defunct(primitive=message)
        #     message = _hash_eip191_message(signable_message)
        # hash_bytes = HexBytes(message)
        # # code taken from https://github.com/ethereum/eth-account/blob/master/eth_account/account.py#L428
        # if len(hash_bytes) != 32:  # pragma: nocover
        #     raise ValueError("The message hash must be exactly 32-bytes")
        # signature_bytes = HexBytes(signature)
        # signature_bytes_standard = to_standard_signature_bytes(signature_bytes)
        # signature_obj = keys.Signature(signature_bytes=signature_bytes_standard)
        # pubkey = signature_obj.recover_public_key_from_msg_hash(hash_bytes)
        return "(str(pubkey),)"

    @classmethod
    def load_contract_interface(cls,
                                file_path: Optional[Path] = None,
                                program_address: Optional[str] = None,
                                rpc_api: Optional[str] = None,
                                ) -> Dict[str, str]:
        """
        Load contract interface.

        :param file_path: the file path to the interface
        :return: the interface
        """
        contract_interface = None
        if program_address is not None and rpc_api is not None:
            try:
                base = PublicKey.find_program_address([], PublicKey(program_address))[0]
                idl_address = PublicKey.create_with_seed(
                    base, "anchor:idl", PublicKey(program_address))
                client = Client(endpoint=rpc_api)
                account_info = client.get_account_info(idl_address)

                account_info_val = account_info["result"]["value"]
                idl_account = _decode_idl_account(
                    b64decode(account_info_val["data"][0])[ACCOUNT_DISCRIMINATOR_SIZE:]
                )
                inflated_idl = _pako_inflate(bytes(idl_account["data"])).decode()
                json_idl = json.loads(inflated_idl)
                return json_idl
            except Exception as e:
                raise Exception("Could not locate IDL")

        elif file_path is not None:
            with open_file(file_path, "r") as interface_file_solana:
                contract_interface = json.load(interface_file_solana)
            return contract_interface
        else:
            raise Exception("Could not locate IDL")
        return contract_interface

    @ staticmethod
    def is_transaction_valid(
        tx: dict,
        seller: Address,
        client: Address,
        tx_nonce: str,
        amount: int,
    ) -> bool:
        """
        Check whether a transaction is valid or not.

        :param tx: the transaction.
        :param seller: the address of the seller.
        :param client: the address of the client.
        :param tx_nonce: the transaction nonce.
        :param amount: the amount we expect to get from the transaction.
        :return: True if the random_message is equals to tx['input']
        """
        is_valid = False
        if tx is not None:
            is_valid = (
                tx.get("input") == tx_nonce
                and tx.get("value") == amount
                and tx.get("from") == client
                and tx.get("to") == seller
            )
        return is_valid

    @ staticmethod
    def is_transaction_settled(tx_receipt: JSONLike) -> bool:
        """
        Check whether a transaction is settled or not.

        :param tx_receipt: the receipt associated to the transaction.
        :return: True if the transaction has been settled, False o/w.
        """
        is_successful = False
        if tx_receipt['result'] is not None:
            is_successful = tx_receipt['result']['meta']['status'] == {'Ok': None}
        return is_successful

    @ staticmethod
    def get_hash(message: bytes) -> str:
        """
        Get the hash of a message.

        :param message: the message to be hashed.
        :return: the hash of the message as a hex string.
        """
        digest = Web3.keccak(message).hex()
        return digest

    @ staticmethod
    def get_contract_address(tx_receipt: JSONLike) -> Optional[str]:
        """
        Retrieve the `contract_address` from a transaction receipt.

        :param tx_receipt: the receipt of the transaction.
        :return: the contract address, if present
        """
        contract_address = cast(Optional[str], tx_receipt.get("contractAddress", None))
        return contract_address

    @ classmethod
    def get_address_from_public_key(cls, public_key: str) -> str:
        """
        Get the address from the public key.

        :param public_key: the public key
        :return: str
        """

        return public_key

    @ staticmethod
    def generate_tx_nonce(self) -> str:
        """
        Generate a unique hash to distinguish transactions with the same terms.

        :param self: .
        :param client: the address of the client.
        :return: return the hash in hex.
        """

        result = self._api.get_recent_blockhash()
        blockhash = result['result']['value']['blockhash']

        return Blockhash(blockhash)

    def get_transfer_transaction(  # pylint: disable=arguments-differ
        self,
        sender_address: Address,
        destination_address: Address,
        amount: int,
        chain_id: Optional[int] = None,
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[JSONLike]:
        """
        Submit a transfer transaction to the ledger.

        :param sender_address: the sender address of the payer.
        :param destination_address: the destination address of the payee.
        :param amount: the amount of wealth to be transferred (in Lamports).
        :param chain_id: the Chain ID of the Ethereum transaction.
        :param raise_on_try: whether the method will raise or log on error
        :param kwargs: keyword arguments
        :return: the transfer transaction
        """
        chain_id = chain_id if chain_id is not None else self._chain_id

        txn = Transaction(fee_payer=PublicKey(sender_address)).add(transfer(TransferParams(
            from_pubkey=PublicKey(sender_address), to_pubkey=PublicKey(destination_address), lamports=amount)))

        return txn

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
        return tx_digest['result']

    @ try_decorator("Unable to send transaction: {}", logger_method="warning")
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
        txn_resp = self._api.send_raw_transaction(tx_signed.serialize())

        return txn_resp

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

        return tx_receipt

    @ try_decorator(
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
        tx_receipt = self._api.get_transaction(tx_digest)  # pylint: disable=no-member
        return tx_receipt

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

    @ try_decorator("Error when attempting getting tx: {}", logger_method="debug")
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
        tx = self._api.get_confirmed_transaction(tx_digest)
        # pylint: disable=no-member
        return tx

    # @ try_decorator(
    #     "Error when attempting getting tx revert reason: {}", logger_method="debug"
    # )
    # def _try_get_revert_reason(self, tx: TxData, **_kwargs: Any) -> str:
    #     """Try to check the revert reason of a transaction.
    #     :param tx: the transaction for which we want to get the revert reason.
    #     :param _kwargs: the keyword arguments. Possible kwargs are:
    #         `raise_on_try`: bool flag specifying whether the method will raise or log on error (used by `try_decorator`)
    #     :return: the revert reason message.
    #     """
    #     # build a new transaction to replay:
    #     replay_tx = {
    #         "to": tx["to"],
    #         "from": tx["from"],
    #         "value": tx["value"],
    #         "data": tx["input"],
    #     }
    # try:
    #     # replay the transaction on the provider
    #     self.api.eth.call(replay_tx, tx["blockNumber"] - 1)
    # except SolidityError as e:
    #     # execution reverted exception
    #     return str(e)
    # except HTTPError as e:
    #     # http exception
    #     raise e
    # else:
    #     # given tx not reverted
    #     raise ValueError(f"The given transaction has not been reverted!\ntx: {tx}")
    def get_contract_instance(
        self, contract_interface: Dict[str, str], contract_address: str
    ) -> Any:
        """
        Get the instance of a contract.

        :param contract_interface: the contract interface.
        :param contract_address: the contract address.
        :return: the contract instance
        """
        program_id = PublicKey(contract_address)
        idl = Idl.from_json(contract_interface)

        pg = Program(idl, program_id)

        return pg

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

    @ try_decorator("Unable to retrieve max_priority_fee: {}", logger_method="warning")
    def _try_get_max_priority_fee(self, **_kwargs: Any) -> str:
        """Try get the gas estimate."""
        return cast(str, self.api.eth.max_priority_fee)

    @ classmethod
    def is_valid_address(cls, address: Address) -> bool:
        """
        Check if the address is valid.

        :param address: the address to validate
        :return: whether the address is valid
        """
        return Web3.isAddress(address)

    @ classmethod
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

        except (Exception, ValueError):  # pragma: nocover
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

        return self._try_get_wealth(address, url)

    @ staticmethod
    @ try_decorator(
        "An error occured while attempting to generate wealth:\n{}",
        logger_method="error",
    )
    def _try_get_wealth(address: Address, url: Optional[str] = None) -> str or None:
        """
        Get wealth from the faucet for the provided address.

        :param address: the address.
        :param url: the url
        """
        if url is None:
            url = DEFAULT_ADDRESS

        solana_client = Client(url)
        response = None
        try:
            response = solana_client.request_airdrop(PublicKey(address), 1000000000)
        except Exception as e:
            msg = e
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
            return response['result']


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
