<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana"></a>

# plugins.aea-ledger-solana.aea`_`ledger`_`solana.solana

Solana module wrapping the public and private key cryptography and ledger api.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi"></a>

## SolanaApi Objects

```python
class SolanaApi(LedgerApi, SolanaHelper)
```

Class to interact with the Solana Web3 APIs.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.__init__"></a>

#### `__`init`__`

```python
def __init__(**kwargs: Any)
```

Initialize the Solana ledger APIs.

**Arguments**:

- `kwargs`: keyword arguments

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.api"></a>

#### api

```python
@property
def api() -> SolanaApiClient
```

Get the underlying API object.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.latest_hash"></a>

#### latest`_`hash

```python
@property
def latest_hash()
```

Get the latest hash.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.system_program"></a>

#### system`_`program

```python
@property
def system_program() -> Pubkey
```

System program.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.sol_to_lamp"></a>

#### sol`_`to`_`lamp

```python
@staticmethod
def sol_to_lamp(sol: float) -> int
```

Solana to lamport value.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.to_account_meta"></a>

#### to`_`account`_`meta

```python
@classmethod
def to_account_meta(cls, pubkey: Union[Pubkey, str], is_signer: bool,
                    is_writable: bool) -> AccountMeta
```

To account meta.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.to_pubkey"></a>

#### to`_`pubkey

```python
@staticmethod
def to_pubkey(key: Union[SolanaCrypto, Keypair, Pubkey, str]) -> Pubkey
```

To pubkey.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.to_keypair"></a>

#### to`_`keypair

```python
@staticmethod
def to_keypair(key: Union[SolanaCrypto, Keypair, str]) -> Keypair
```

To keypair object.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.pda"></a>

#### pda

```python
@staticmethod
def pda(seeds: Sequence[bytes], program_id: Pubkey) -> Pubkey
```

Create TX PDA

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.create_pda"></a>

#### create`_`pda

```python
@staticmethod
def create_pda(from_address: str, new_account_address: str, base_address: str,
               seed: str, lamports: int, space: int, program_id: str)
```

Build a create pda transaction.

**Arguments**:

- `from_address`: the sender public key
- `new_account_address`: the new account public key
- `base_address`: base address
- `seed`: seed
- `lamports`: the amount of lamports to send
- `space`: the space to allocate
- `program_id`: the program id

**Returns**:

the tx, if present

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.add_nonce"></a>

#### add`_`nonce

```python
def add_nonce(tx: dict) -> JSONLike
```

Check whether a transaction is valid or not.

**Arguments**:

- `tx`: the transaction.

**Returns**:

True if the random_message is equals to tx['input']

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.wait_get_receipt"></a>

#### wait`_`get`_`receipt

```python
def wait_get_receipt(
    transaction_digest: str,
    max_supported_transaction_version: Optional[int] = None
) -> Tuple[Optional[JSONLike], bool]
```

Wait for the transaction to be settled and return the receipt.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.construct_and_settle_tx"></a>

#### construct`_`and`_`settle`_`tx

```python
def construct_and_settle_tx(account1: SolanaCrypto, account2: SolanaCrypto,
                            tx_params: dict) -> Tuple[str, JSONLike, bool]
```

Construct and settle a transaction.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.update_with_gas_estimate"></a>

#### update`_`with`_`gas`_`estimate

```python
def update_with_gas_estimate(transaction: JSONLike) -> JSONLike
```

Attempts to update the transaction with a gas estimate

**NOT APPLICABLE**

**Arguments**:

- `transaction`: the transaction

**Returns**:

the updated transaction

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_balance"></a>

#### get`_`balance

```python
def get_balance(address: Address, raise_on_try: bool = False) -> Optional[int]
```

Get the balance of a given account.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_state"></a>

#### get`_`state

```python
def get_state(callable_name: str,
              *args: Any,
              raise_on_try: bool = False,
              **kwargs: Any) -> Optional[JSONLike]
```

Call a specified function on the underlying ledger API.

This usually takes the form of a web request to be waited synchronously.

**Arguments**:

- `callable_name`: the name of the API function to be called.
- `args`: the positional arguments for the API function.
- `raise_on_try`: whether the method will raise or log on error
- `kwargs`: the keyword arguments for the API function.

**Returns**:

the ledger API response.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_transfer_transaction"></a>

#### get`_`transfer`_`transaction

```python
def get_transfer_transaction(sender_address: Address,
                             destination_address: Address, amount: int,
                             tx_fee: int, tx_nonce: str,
                             **kwargs: Any) -> Optional[JSONLike]
```

Submit a transfer transaction to the ledger.

**Arguments**:

- `sender_address`: the sender address of the payer.
- `destination_address`: the destination address of the payee.
- `amount`: the amount of wealth to be transferred.
- `tx_fee`: the transaction fee.
- `tx_nonce`: verifies the authenticity of the tx
- `kwargs`: the keyword arguments.

**Returns**:

the transfer transaction

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.send_signed_transaction"></a>

#### send`_`signed`_`transaction

```python
def send_signed_transaction(tx_signed: JSONLike,
                            raise_on_try: bool = False) -> Optional[str]
```

Send a signed transaction and wait for confirmation.

**Arguments**:

- `tx_signed`: the signed transaction
- `raise_on_try`: whether the method will raise or log on error

**Returns**:

tx_digest, if present

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.send_signed_transactions"></a>

#### send`_`signed`_`transactions

```python
def send_signed_transactions(signed_transactions: List[JSONLike],
                             raise_on_try: bool = False,
                             **kwargs: Any) -> Optional[List[str]]
```

Atomically send multiple of transactions.

**Arguments**:

- `signed_transactions`: the signed transactions to bundle together and send.
- `raise_on_try`: whether the method will raise or log on error
- `kwargs`: the keyword arguments.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_transaction_receipt"></a>

#### get`_`transaction`_`receipt

```python
def get_transaction_receipt(
        tx_digest: str,
        max_supported_transaction_version: Optional[int] = None,
        retries: Optional[int] = None,
        raise_on_try: bool = False) -> Optional[JSONLike]
```

Get the transaction receipt for a transaction digest.

**Arguments**:

- `tx_digest`: the digest associated to the transaction.
- `max_supported_transaction_version`: The max transaction version to return in responses.
- `retries`: The max amount of retries for fetching the receipt.
- `raise_on_try`: whether the method will raise or log on error

**Returns**:

the tx receipt, if present

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_transaction"></a>

#### get`_`transaction

```python
def get_transaction(tx_digest: str,
                    max_supported_transaction_version: Optional[int] = None,
                    raise_on_try: bool = False) -> Optional[JSONLike]
```

Get the transaction for a transaction digest.

**Arguments**:

- `tx_digest`: the digest associated to the transaction.
- `max_supported_transaction_version`: The max transaction version to return in responses.
- `raise_on_try`: whether the method will raise or log on error

**Returns**:

the tx, if present

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.create_default_account"></a>

#### create`_`default`_`account

```python
@staticmethod
def create_default_account(from_address: str,
                           new_account_address: str,
                           lamports: int,
                           space: int,
                           program_id: Optional[str] = SYS_PROGRAM_ID)
```

Build a create account transaction.

**Arguments**:

- `from_address`: the sender public key
- `new_account_address`: the new account public key
- `lamports`: the amount of lamports to send
- `space`: the space to allocate
- `program_id`: the program id

**Returns**:

the tx, if present

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_contract_instance"></a>

#### get`_`contract`_`instance

```python
def get_contract_instance(contract_interface: Dict[str, str],
                          contract_address: Optional[str] = None) -> Any
```

Get the instance of a contract.

**Arguments**:

- `contract_interface`: the contract interface.
- `contract_address`: the contract address.

**Returns**:

the contract instance

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_deploy_transaction"></a>

#### get`_`deploy`_`transaction

```python
def get_deploy_transaction(contract_interface: Dict[str, str],
                           deployer_address: Address,
                           raise_on_try: bool = False,
                           **kwargs: Any) -> Optional[JSONLike]
```

Get the transaction to deploy the smart contract.

**Arguments**:

- `contract_interface`: the contract interface.
- `deployer_address`: The address that will deploy the contract.
- `raise_on_try`: whether the method will raise or log on error
- `kwargs`: the keyword arguments.

**Returns**:

`tx`: the transaction dictionary.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.contract_method_call"></a>

#### contract`_`method`_`call

```python
def contract_method_call(contract_instance: Any, method_name: str,
                         **method_args: Any) -> Optional[JSONLike]
```

Call a contract's method

**TOBEIMPLEMENTED**

**Arguments**:

- `contract_instance`: the contract to use
- `method_name`: the contract method to call
- `method_args`: the contract call parameters
# noqa: DAR202

**Returns**:

the call result

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.build_transaction"></a>

#### build`_`transaction

```python
def build_transaction(contract_instance: Any,
                      method_name: str,
                      method_args: Optional[Dict[Any, Any]],
                      tx_args: Optional[Dict[Any, Any]],
                      raise_on_try: bool = False) -> Optional[JSONLike]
```

Prepare a transaction

**Arguments**:

- `contract_instance`: the contract to use
- `method_name`: the contract method to call
- `method_args`: the contract parameters
- `tx_args`: the transaction parameters
- `raise_on_try`: whether the method will raise or log on error

**Returns**:

the transaction

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.build_instruction"></a>

#### build`_`instruction

```python
def build_instruction(
        contract_instance: Program,
        method_name: str,
        data: List[Any],
        accounts: Dict[str, Pubkey],
        remaining_accounts: Optional[List[AccountMeta]] = None) -> JSONLike
```

Prepare an instruction

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.serialize_tx"></a>

#### serialize`_`tx

```python
def serialize_tx(
    tx: Union[Dict, SolanaTransaction, SoldersTransaction,
              SoldersVersionedTransaction]
) -> Dict
```

Serialize transaction to solders transaction compatible json object.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.deserialize_tx"></a>

#### deserialize`_`tx

```python
def deserialize_tx(
    tx: Union[Dict, SolanaTransaction, SoldersTransaction,
              SoldersVersionedTransaction]
) -> SolanaTransaction
```

Deserialize transaction to a solana transaction object.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.serialize_ix"></a>

#### serialize`_`ix

```python
def serialize_ix(ix: Instruction) -> Dict
```

Serialize instruction.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.deserialize_ix"></a>

#### deserialize`_`ix

```python
def deserialize_ix(ix: Dict) -> Instruction
```

Deserialize instruction.

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.get_transaction_transfer_logs"></a>

#### get`_`transaction`_`transfer`_`logs

```python
def get_transaction_transfer_logs(
        contract_instance: Any,
        tx_hash: str,
        max_supported_transaction_version: Optional[int] = None,
        target_address: Optional[str] = None) -> Optional[JSONLike]
```

Get all transfer events derived from a transaction.

**Arguments**:

- `contract_instance`: contract instance
- `tx_hash`: the transaction hash
- `max_supported_transaction_version`: The max transaction version to return in responses.
- `target_address`: optional address to filter tranfer events to just those that affect it

**Returns**:

the transfer logs

<a id="plugins.aea-ledger-solana.aea_ledger_solana.solana.SolanaApi.filter_event"></a>

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

