<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai"></a>

# plugins.aea-ledger-fetchai.aea`_`ledger`_`fetchai.fetchai

Fetchai module wrapping the public and private key cryptography and ledger api.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIHelper"></a>

## FetchAIHelper Objects

```python
class FetchAIHelper(CosmosHelper)
```

Helper class usable as Mixin for FetchAIApi or as standalone class.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAICrypto"></a>

## FetchAICrypto Objects

```python
class FetchAICrypto(CosmosCrypto)
```

Class wrapping the Entity Generation from Fetch.AI ledger.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi"></a>

## FetchAIApi Objects

```python
class FetchAIApi(_CosmosApi, FetchAIHelper)
```

Class to interact with the Fetch ledger APIs.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi.__init__"></a>

#### `__`init`__`

```python
def __init__(**kwargs: Any) -> None
```

Initialize the Fetch.ai ledger APIs.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi.contract_method_call"></a>

#### contract`_`method`_`call

```python
def contract_method_call(contract_instance: Any, method_name: str,
                         **method_args: Any) -> Optional[JSONLike]
```

Call a contract's method

**Arguments**:

- `contract_instance`: the contract to use
- `method_name`: the contract method to call
- `method_args`: the contract call parameters

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi.build_transaction"></a>

#### build`_`transaction

```python
def build_transaction(contract_instance: Any,
                      method_name: str,
                      method_args: Optional[Dict],
                      tx_args: Optional[Dict],
                      raise_on_try: bool = False) -> Optional[JSONLike]
```

Prepare a transaction

**Arguments**:

- `contract_instance`: the contract to use
- `method_name`: the contract method to call
- `method_args`: the contract parameters
- `tx_args`: the transaction parameters
- `raise_on_try`: whether the method will raise or log on error

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi.get_transaction_transfer_logs"></a>

#### get`_`transaction`_`transfer`_`logs

```python
def get_transaction_transfer_logs(
        contract_instance: Any,
        tx_hash: str,
        target_address: Optional[str] = None) -> Optional[JSONLike]
```

Get all transfer events derived from a transaction.

**Arguments**:

- `contract_instance`: the contract
- `tx_hash`: the transaction hash
- `target_address`: optional address to filter transfer events to just those that affect it

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi.send_signed_transactions"></a>

#### send`_`signed`_`transactions

```python
def send_signed_transactions(signed_transactions: List[JSONLike],
                             raise_on_try: bool = False,
                             **kwargs: Any) -> Optional[List[str]]
```

Simulate and send a bundle of transactions.

This operation is not supported for fetchai.

**Arguments**:

- `signed_transactions`: the raw signed transactions to bundle together and send.
- `raise_on_try`: whether the method will raise or log on error.
- `kwargs`: the keyword arguments.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIApi.filter_event"></a>

#### filter`_`event

```python
def filter_event(event: Any, match_single: Dict[str, Any],
                 match_any: Dict[str, Any], to_block: int, from_block: int,
                 batch_size: int, max_retries: int, reduce_factor: float,
                 timeout: int) -> Optional[JSONLike]
```

Filter an event using batching to avoid RPC timeouts.

**Arguments**:

- `event`: the event to filter for.
- `match_single`: the filter parameters with value checking against the event abi. It allows for defining a single match value.
- `match_any`: the filter parameters with value checking against the event abi. It allows for defining multiple match values.
- `to_block`: the block to which to filter.
- `from_block`: the block from which to start filtering.
- `batch_size`: the blocks' batch size of the filtering.
- `max_retries`: the maximum number of retries.
- `reduce_factor`: the percentage by which the batch size is reduced in case of a timeout.
- `timeout`: a timeout in seconds to interrupt the operation in case the RPC request hangs.

<a id="plugins.aea-ledger-fetchai.aea_ledger_fetchai.fetchai.FetchAIFaucetApi"></a>

## FetchAIFaucetApi Objects

```python
class FetchAIFaucetApi(CosmosFaucetApi)
```

Fetchai testnet faucet API.

