# Proposal: multichain & gas fixes (PR covering #780, #775, #754, #2479)

Single PR on `valory-xyz/open-aea`, minimal diff per issue, four independent patches co-located. Delete this file when PR merges.

## Per-issue fix

### #780 — L2 gas: auto-call `get_l1_data_fee`

- Helper exists at `plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py:1323` (from PR #784) but has **zero internal callers**.
- Add `OP_STACK_CHAIN_IDS = frozenset({10, 8453, 34443, 252})` (Optimism, Base, Mode, Fraxtal).
- In `get_transfer_transaction`, after the gas-pricing block (~line 1166), if `self._chain_id in OP_STACK_CHAIN_IDS` call `get_l1_data_fee` and fold the returned fee into `transaction["value"]`.
- ~8 LoC + one integration test.

### #775 — Per-chain fallback gas + informative warning

- 10 of 11 chain blocks in `packages/valory/connections/ledger/connection.yaml` ship copy-pasted mainnet fallbacks (20 gwei / 3 gwei). Only `mode` is tuned.
- Tune per-chain `fallback_estimate` with values sourced from each chain's documented minimum priority fee or recent median base fee (no fabrication).
- Rewrite the warning at `ethereum.py:277–282` to name the fallback values being used and point at the `gas_price_strategies` kwarg override.
- `autonomy packages lock` after.

### #754 — Chain-name routing

- Dispatch at `packages/valory/connections/ledger/base.py:172` needs both `ledger_id="ethereum"` and `chain_id="optimism"` because registry keys are distinct from per-chain config keys.
- Between lines 170 and 172, add: if `ledger_id` is in `_api_configs` but not a registered ledger, rewrite it to the EVM registry key. Old call shape keeps working forever.
- ~6 LoC + one parametrized dispatcher test. No protocol change, no hash cascade.

### #2479 — Re-enable `open-aea-ledger-solana`

- **Issue body is mis-diagnosed.** `anchorpy` has never depended on `cachetools`. Verified against PyPI `requires_dist` for 0.18/0.19/0.21.
- Real pin: `solana-py 0.30.x/0.32.x` → `cachetools>=4.2.2,<5.0.0`. `solana>=0.36.1` drops it, which requires `anchorpy>=0.21.0`.
- Bump `plugins/aea-ledger-solana/setup.py`: `anchorpy>=0.21.0,<0.22.0`, `solana>=0.36.1,<1.0.0`, `solders>=0.21.0,<1.0.0`. Patch-bump plugin `2.2.1 → 2.2.2`.
- Downstream uncomment in `open-autonomy/pyproject.toml` is a **follow-up PR**, not part of this one.

## Overall design

Independent patches co-located. No shared abstraction — four small, narrowly scoped edits across four different files. Four commits (one per issue) plus one packages-lock commit. PR body references all four issue numbers.

## Decisions needed before implementation

### (a) #775 — fallback shape

1. YAML-only per-chain values in `connection.yaml` *(recommended)*
2. Plugin-side per-chain defaults keyed by chain-id (helps direct callers that bypass the connection)
3. Both

Also: confirm the specific gwei values per chain before they land (list will be posted inline in the PR for review).

### (b) #754 — how does the dispatcher know a config entry routes to the ethereum plugin vs. solana/cosmos/…?

1. Default-to-ethereum when `ledger_id` is in configs but not registered
2. Explicit `ledger_plugin: ethereum` field on each chain block in `connection.yaml` *(recommended — survives #2479 solana re-enable cleanly)*
3. Chain-id heuristic (brittle)

Deprecation posture for old `(ledger_id="ethereum", chain_id="optimism")` shape: stay silent and document the new form as preferred *(recommended)* vs. deprecation warning.

### (c) #780 — OP-stack chain detection

1. Hardcoded chain-id frozenset *(recommended, this PR)*
2. Runtime probe (extra RPC per tx)
3. YAML flag `op_stack: true` (requires b.2 to land first — follow-up PR)

### (d) #2479 — solana plugin version bump

1. Patch `2.2.1 → 2.2.2` *(recommended unless internal API audit finds breakage)*
2. Minor `2.2.1 → 2.3.0` (if solana-py 0.29→0.36 / anchorpy 0.18→0.21 breaks plugin-internal usage)

## Out of scope

- Refactoring `get_transfer_transaction`'s gas-pricing ladder
- Driving OP-stack set from YAML (depends on (b.2))
- Fixing mainnet-flavoured `DEFAULT_GAS_PRICE_STRATEGIES` module constant for direct callers
- Touching sibling plugins (`hwi` / `fetchai` / `cosmos`)
- Renaming the `chain_id` message field
- Second PR on `open-autonomy` to flip the solana pin
- Upgrading `tomte` / downgrading `tox`
- Retuning `fallback_estimate` values in downstream-service YAMLs

## Verification

- `tox -e black -e isort -e flake8 -e pylint -e mypy -e darglint` on touched packages
- `autonomy analyse docstrings --update` + `autonomy packages lock`
- `tox -e py3.11-linux`
- Local smoke in `open-autonomy`: uncomment solana line, `poetry lock --no-update` resolves, revert
- Manual reproduction of the #775 reproducer on Base

## Files touched (pre-approved scope)

- `plugins/aea-ledger-solana/setup.py`, `plugins/aea-ledger-solana/HISTORY.md`
- `packages/valory/connections/ledger/base.py`
- `packages/valory/connections/ledger/connection.yaml`
- `plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py`
- `plugins/aea-ledger-ethereum/tests/test_ethereum.py`
- `packages/valory/connections/ledger/tests/`
- auto-regenerated: `HISTORY.md`, `packages/packages.json`

Growth beyond this list is a scope violation.
