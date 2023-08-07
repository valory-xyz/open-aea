<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32"></a>

# plugins.aea-ledger-ethereum-hwi.aea`_`ledger`_`ethereum`_`hwi.bip32

BIP32 utils

Original implementation: https://github.com/LedgerHQ/apduboy/blob/master/apduboy/lib/bip32.py

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Level"></a>

## Level Objects

```python
@dataclass
class Level()
```

Level separator.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Level.value"></a>

#### value

```python
@property
def value() -> int
```

Value

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Level.__str__"></a>

#### `__`str`__`

```python
def __str__() -> str
```

String representation.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation"></a>

## Derivation Objects

```python
@dataclass
class Derivation()
```

Path derivation

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.__truediv__"></a>

#### `__`truediv`__`

```python
def __truediv__(level: int) -> "Derivation"
```

Combine multiple path derivations using `/` operator.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.account"></a>

#### account

```python
@property
def account() -> int
```

Account value.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.parent"></a>

#### parent

```python
@property
def parent() -> "Derivation"
```

Parent value.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.path"></a>

#### path

```python
@property
def path() -> str
```

Calculated path.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.to_list"></a>

#### to`_`list

```python
def to_list() -> List[int]
```

Convert to list.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.depth"></a>

#### depth

```python
@property
def depth() -> int
```

Depth.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.__repr__"></a>

#### `__`repr`__`

```python
def __repr__()
```

String representation.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.Derivation.__str__"></a>

#### `__`str`__`

```python
def __str__()
```

String representation.

<a id="plugins.aea-ledger-ethereum-hwi.aea_ledger_ethereum_hwi.bip32.h"></a>

#### h

```python
def h(value: int) -> int
```

Wrap value.

