# -*- coding: utf-8 -*-
# ------------------------------------------------------------------------------
#
#   Copyright 2022-2025 Valory AG
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

"""Fetchai module wrapping the public and private key cryptography and ledger api."""

from typing import Any, Dict, List, Optional

from aea_ledger_cosmos.cosmos import (
    CosmosCrypto,
    CosmosFaucetApi,
    CosmosHelper,
    MAXIMUM_GAS_AMOUNT,
    _CosmosApi,
)

from aea.common import JSONLike


_ = MAXIMUM_GAS_AMOUNT
_FETCHAI = "fetchai"
_FETCH = "fetch"
TESTNET_NAME = "testnet"
FETCHAI_TESTNET_FAUCET_URL = "https://faucet-dorado.fetch.ai"
DEFAULT_ADDRESS = "https://rest-dorado.fetch.ai:443"
DEFAULT_CURRENCY_DENOM = "atestfet"
DEFAULT_CHAIN_ID = "dorado-1"


class FetchAIHelper(CosmosHelper):
    """Helper class usable as Mixin for FetchAIApi or as standalone class."""

    address_prefix = _FETCH


class FetchAICrypto(CosmosCrypto):  # pylint: disable=W0223
    """Class wrapping the Entity Generation from Fetch.AI ledger."""

    identifier = _FETCHAI
    helper = FetchAIHelper


class FetchAIApi(_CosmosApi, FetchAIHelper):
    """Class to interact with the Fetch ledger APIs."""

    identifier = _FETCHAI

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the Fetch.ai ledger APIs."""
        if "address" not in kwargs:
            kwargs["address"] = DEFAULT_ADDRESS  # pragma: nocover
        if "denom" not in kwargs:
            kwargs["denom"] = DEFAULT_CURRENCY_DENOM
        if "chain_id" not in kwargs:
            kwargs["chain_id"] = DEFAULT_CHAIN_ID
        super().__init__(**kwargs)

    def contract_method_call(
        self,
        contract_instance: Any,
        method_name: str,
        **method_args: Any,
    ) -> Optional[JSONLike]:
        """Call a contract's method

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract call parameters
        """
        raise NotImplementedError  # pragma: nocover

    def build_transaction(  # pylint: disable=too-many-positional-arguments
        self,
        contract_instance: Any,
        method_name: str,
        method_args: Optional[Dict],
        tx_args: Optional[Dict],
        raise_on_try: bool = False,
    ) -> Optional[JSONLike]:
        """Prepare a transaction

        :param contract_instance: the contract to use
        :param method_name: the contract method to call
        :param method_args: the contract parameters
        :param tx_args: the transaction parameters
        :param raise_on_try: whether the method will raise or log on error
        """
        raise NotImplementedError  # pragma: nocover

    def get_transaction_transfer_logs(
        self,
        contract_instance: Any,
        tx_hash: str,
        target_address: Optional[str] = None,
    ) -> Optional[JSONLike]:
        """
        Get all transfer events derived from a transaction.

        :param contract_instance: the contract
        :param tx_hash: the transaction hash
        :param target_address: optional address to filter transfer events to just those that affect it
        """
        raise NotImplementedError  # pragma: nocover

    def send_signed_transactions(
        self,
        signed_transactions: List[JSONLike],
        raise_on_try: bool = False,
        **kwargs: Any,
    ) -> Optional[List[str]]:
        """
        Simulate and send a bundle of transactions.

        This operation is not supported for fetchai.

        :param signed_transactions: the raw signed transactions to bundle together and send.
        :param raise_on_try: whether the method will raise or log on error.
        :param kwargs: the keyword arguments.
        """
        raise NotImplementedError(  # pragma: nocover
            f"Sending a bundle of transactions is not supported for the {self.identifier} plugin"
        )

    def filter_event(  # pylint: disable=too-many-positional-arguments
        self,
        event: Any,
        match_single: Dict[str, Any],
        match_any: Dict[str, Any],
        to_block: int,
        from_block: int,
        batch_size: int,
        max_retries: int,
        reduce_factor: float,
        timeout: int,
    ) -> Optional[JSONLike]:
        """Filter an event using batching to avoid RPC timeouts.

        :param event: the event to filter for.
        :param match_single: the filter parameters with value checking against the event abi. It allows for defining a single match value.
        :param match_any: the filter parameters with value checking against the event abi. It allows for defining multiple match values.
        :param to_block: the block to which to filter.
        :param from_block: the block from which to start filtering.
        :param batch_size: the blocks' batch size of the filtering.
        :param max_retries: the maximum number of retries.
        :param reduce_factor: the percentage by which the batch size is reduced in case of a timeout.
        :param timeout: a timeout in seconds to interrupt the operation in case the RPC request hangs.
        """
        raise NotImplementedError(  # pragma: nocover
            f"Custom events' filtering is not supported for the {self.identifier} plugin"
        )


class FetchAIFaucetApi(CosmosFaucetApi):
    """Fetchai testnet faucet API."""

    identifier = _FETCHAI
    testnet_name = TESTNET_NAME
    testnet_faucet_url = FETCHAI_TESTNET_FAUCET_URL
