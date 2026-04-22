# Proposal: L2 gas fixes (PR covering [#780] and [#775])

Scope narrowed to [#780] + [#775] only. Issues [#754] and [#2479] deferred — see appendix.

Single PR on `valory-xyz/open-aea`. Minimum diff. Delete this file when PR merges.

## Responsibility split (guiding principle)

Three distinct concerns are tangled in this problem space. Keeping each at its right layer is what lets this PR ship without fighting the Jan-2025 review thread.

| Concern | Layer | Rationale |
| --- | --- | --- |
| **Protocol truth** — which RPC to call on which chain to get the real L1 data fee | **Plugin** (`aea-ledger-ethereum`) | The plugin owns RPC I/O. Deterministic, network-level, not a policy choice. |
| **Chain identity** — which chain IDs belong to which L2 fee family (OP-stack, Arbitrum, …) | **Plugin** (private constants) | Static protocol knowledge; consumers shouldn't re-encode it. |
| **Deployment policy** — what gwei fallback to use when RPC estimation fails | **Config layer** (`connection.yaml`) + explicit `gas_price_strategies=` kwarg | Policy, not physics. Different deployments legitimately pick different numbers. |

## Per-issue fix

### [#780] — L2 gas: generalise `get_l1_data_fee`, auto-call from tx build

The helper at `plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py:1323` (from PR [#784]) has zero internal callers and only covers OP-stack. All protocol-truth work, all in the plugin.

**Fix:**

1. Generalise `get_l1_data_fee(tx) -> int` to dispatch internally based on `self._chain_id`:
    - OP-stack chains → existing `GasPriceOracle.getL1Fee(bytes)` at `0x420000000000000000000000000000000000000F`
    - Arbitrum chains → `NodeInterface.gasEstimateL1Component(address, bool, bytes)` at `0x00000000000000000000000000000000000000C8`
    - All other chain IDs → return 0 (no-op)

    ABI + addresses pinned to upstream docs in code comments. Chain-id membership held in private module-level frozensets (`_OP_STACK_CHAIN_IDS`, `_ARBITRUM_CHAIN_IDS`) — not exported. Consumers never need to know.

2. Auto-call from `get_transfer_transaction` after the gas-pricing block. **Expose the returned value as a new `tx['l1DataFee']` field when non-zero. Do not modify `tx['value']` or `tx['gas']`.**

    Why not fold into `value`: `value` on a contract call is `msg.value` to the contract. Changing it to cover the sequencer's L1 charge breaks contract-call semantics for every L2 tx. The reproducer in [#775] happens to be a drain (`to` is an EOA, no `data`), so `value`-folding would coincidentally fix it — but at the cost of corrupting contract calls. A new additive field is strictly safer.

    Why not `gas` (limit): L1 fee isn't billed per unit of L2 gas; bumping the limit doesn't cover it and scrambles the gas-limit-vs-price abstraction.

3. Downstream hand-off: middleware's `estimate_transfer_tx_fee` at `olas-operate-middleware/operate/utils/gnosis.py:566–569` already does `chain_fee = gas * maxFeePerGas + get_l1_data_fee(tx)` — exactly the pattern we're formalising. After this PR lands, that function reads `tx.get('l1DataFee', 0)` instead of calling the helper directly, and drops the `(ARBITRUM_ONE, BASE, OPTIMISM, MODE)` tuple (which was also silently wrong for Arbitrum because the existing helper only covered OP-stack). That cleanup is a separate follow-up PR in middleware.

**Diff:** +20 LoC in `ethereum.py` (dispatcher + Arbitrum branch + 1-line wire-up), +30 LoC tests (OP-stack, Arbitrum, non-L2). Two chain-id sets + two ABI snippets.

### [#775] — Tune the YAML, improve the warning

The actual in-repo bug: `packages/valory/connections/ledger/connection.yaml` ships 10 of 11 chain blocks with mainnet `fallback_estimate` values (20 gwei max / 3 gwei tip) copy-pasted. Only `mode` is tuned. When the primary EIP-1559 estimator fails, every non-mainnet service that uses this connection falls back to wildly wrong numbers. This is what both reviewers pointed at in the Jan-2025 thread — the override machinery exists; the shipped values are wrong.

**Fix:**

1. Tune `packages/valory/connections/ledger/connection.yaml` per-chain `fallback_estimate` blocks. Values lifted 1-for-1 from the middleware patch at `olas-operate-middleware/operate/ledger/__init__.py:115–142` (already running in production):

    - `base` (8453), `optimism` (10), `mode` (34443) → `maxFeePerGas: 5 gwei`
    - `polygon` (137) → `maxFeePerGas: 6000 gwei`, `max_gas_fast: 10000` (Polygon bursts needed)
    - `ethereum`, `gnosis`, `arbitrum`, `celo`, `bnb`, `zksync`, `fraxtal` → keep existing 20 / 3 gwei

    No fabrication. If a chain is missing from the middleware patch, it stays on the existing value. Operators who want different numbers override via `gas_price_strategies=` kwarg (unchanged escape hatch, already documented in-thread and shipping in [olas-operate-app#667](https://github.com/valory-xyz/olas-operate-app/pull/667)).

2. Improve the fallback warning in `plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py:277–282`. Current message: `"An error occurred while estimating gas price. Falling back."` — unhelpful. New message must:
    - name the chain_id
    - name the values actually being used
    - point at `gas_price_strategies=` as the supported override

    This is the only unanimous consensus item from the Jan-2025 thread (all three reviewers agreed). Concrete message text to be reviewed line-by-line in the PR.

3. Regenerate the connection package hash (`autonomy packages lock`).

**Explicitly NOT done:**

- Do **not** add a `CHAIN_FALLBACK_ESTIMATES` dict to the ethereum plugin. The ledger stays a thin RPC wrapper. @Adamantios's Jan-2025 objection ("per-chain defaults don't belong on the ledger") holds. `BASE_FEE_MULTIPLIER`'s chain-id branching is a weak precedent — it's a protocol-behaviour adjustment, not a policy number.
- Do **not** add a new `make_chain_ledger_api` wrapper to `aea.crypto.registries`. That's a separate API design discussion; if later desired, it can read from the already-correct YAML.
- Do **not** touch the module-level `FALLBACK_ESTIMATE` constant (`ethereum.py:113`). It's fine as a Gnosis-ish default for the rare direct-caller path; direct callers are expected to pass `gas_price_strategies=` if they want tuned numbers (confirmed working and documented in the thread).

**Downstream consequence.** Middleware's `make_chain_ledger_api` (the whole per-chain branching block) can eventually shrink to a thin `make_ledger_api` call once callers migrate to the connection-mediated path. That shrink is not forced — middleware may keep its own overrides if it wants tighter policy. Middleware's `# TODO backport to open aea/autonomy` comments partially resolve (the *what* and *where* are now answered; the *shape* of the backport remains a policy layer decision, not a protocol one).

**Diff:** ~33 YAML lines changed + 1 regenerated hash + ~5 LoC warning rewrite + ~15 LoC tests for the new warning format. No change to plugin constants or API surface.

### What [#775] does NOT fix (say this in the PR body)

The reproducer in [#775]'s body crashes on **gas-limit estimation** (`tx['gas']` returns 0 or a pathological number for a safe-deploy on Base), not on gas-fee fallback. `eth_estimateGas` misbehaving is a separate bug requiring its own investigation. This PR only fixes the fee-side safety net — it reduces the blast radius when that safety net fires but does not prevent the underlying estimator failure. File a separate issue once we have cleaner repro data for the `eth_estimateGas` pathology on Base.

## Overall design

Two independent patches, one PR. Minimal coupling: [#780] is all plugin code, [#775] is mostly YAML with one warning rewrite. Three commits:

1. `fix(ethereum): generalise get_l1_data_fee for OP-stack and Arbitrum; expose L1 fee on tx` (#780)
2. `fix(ledger): tune per-chain fallback_estimate in connection.yaml` (#775)
3. `fix(ethereum): improve fallback warning message` (#775)

## Decisions needed before implementation

### (a) [#780] — how to expose the L1 fee

1. **New additive field `tx['l1DataFee']` when non-zero, never modify `value`/`gas`** *(recommended)* — clean, additive, no semantics change for existing callers. Middleware's drain path reads the new field; non-drain callers ignore it and are unaffected.
2. Conditional fold into `value` when tx has no `data`, separate field on contract calls — fixes the reproducer "for free" but introduces a case-analysis burden on reviewers and consumers. Rejected.
3. Always fold into `value` — corrupts contract-call semantics. Rejected.
4. Bump `gas` — wrong abstraction. Rejected.

### (b) [#780] — chain detection method

1. **Hardcoded private chain-id frozensets in the plugin** *(recommended)* — matches how every production OP-stack tooling does it (viem, ethers-rs).
2. Runtime probe (call `getL1Fee` on every chain and see if it returns) — one extra RPC per tx, rejected.
3. Public exported chain-id constants — leaks implementation detail; consumers shouldn't branch on this.

### (c) [#775] — YAML values for `fallback_estimate`

Lift from middleware's `make_chain_ledger_api`. Confirm before commit:

- Base / Optimism / Mode → `maxFeePerGas: 5 gwei`
- Polygon → `maxFeePerGas: 6000 gwei`, `max_gas_fast: 10000`
- Ethereum / Gnosis / Arbitrum / Celo / BNB / zkSync / Fraxtal → keep existing 20 / 3 gwei

Open sub-question: Arbitrum at 20 / 3 gwei is technically too high (typical Arbitrum gas is sub-gwei), but middleware doesn't tune it and no one has complained. Vote: leave as-is, tune in a follow-up if traffic data motivates it.

## Out of scope

- Refactoring `get_transfer_transaction`'s gas-pricing ladder
- Fixing the upstream `eth_estimateGas` pathology on Base (separate investigation)
- Chain-name routing at dispatch ([#754] — appendix)
- Solana plugin dep conflict ([#2479] — appendix)
- Touching sibling plugins (`aea-ledger-ethereum-hwi` / `aea-ledger-fetchai` / `aea-ledger-cosmos`)
- Retuning `fallback_estimate` in downstream-service YAMLs (trader / market-creator / watchdog — each repo's owners)
- Adding a `make_chain_ledger_api` wrapper to `aea.crypto.registries` (separate API design)
- Removing middleware's ad-hoc `(ARBITRUM_ONE, BASE, OPTIMISM, MODE)` tuple in `operate/utils/gnosis.py:566–569` (follow-up PR on middleware after this ships)

## Verification

- `tox -e black -e isort -e flake8 -e pylint -e mypy -e darglint` on the ethereum plugin + ledger connection
- `tox -e py3.11-linux` (plugin tests + connection tests)
- `autonomy packages lock` regenerates the ledger connection hash cleanly
- Manual run of `repro_gas_issue.py` on Gnosis + Base — expect (post-fix) Base shows `tx['l1DataFee']` populated and `tx['value']` unchanged; fallback inspection via the connection reads 5 gwei on Base instead of 20
- Middleware smoke: read `tx['l1DataFee']` from the new field, confirm drain math matches the current pre-fix value

## Files touched (pre-approved scope)

- `plugins/aea-ledger-ethereum/aea_ledger_ethereum/ethereum.py` — [#780] `get_l1_data_fee` generalisation, wire-up, new `tx['l1DataFee']` field; [#775] warning message rewrite
- `plugins/aea-ledger-ethereum/tests/test_ethereum.py` — tests for both
- `plugins/aea-ledger-ethereum/HISTORY.md`
- `packages/valory/connections/ledger/connection.yaml` — [#775] tuned `fallback_estimate` per chain
- `packages/valory/connections/ledger/connection.yaml` hash regen via `autonomy packages lock` (auto-touches `packages/packages.json`)

Growth beyond this list is a scope violation.

---

## Appendix — deferred issues

Kept here for context / future work. Not addressed in this PR.

### [#754] — Chain-name routing

Dispatch at `packages/valory/connections/ledger/base.py:172` requires both `ledger_id="ethereum"` and `chain_id="optimism"` because registry keys are distinct from per-chain config keys. Fix sketch: between lines 170 and 172 in `dispatch`, if `ledger_id` is in `_api_configs` but not a registered ledger, rewrite it to the EVM registry key. Old call shape keeps working forever. ~6 LoC + one parametrized dispatcher test. No protocol change.

Open design call: how does the dispatcher know a config entry routes to the ethereum plugin vs. solana/cosmos/…? Options — default-to-ethereum (simple, brittle), explicit `ledger_plugin: ethereum` YAML field (recommended — survives [#2479] re-enable cleanly), chain-id heuristic (brittle). Deprecation posture for old shape: stay silent and document the new form as preferred.

### [#2479] — Re-enable `open-aea-ledger-solana`

Issue body is mis-diagnosed: `anchorpy` has never depended on `cachetools` (verified against PyPI `requires_dist` for 0.18 / 0.19 / 0.21). Real pin is in `solana-py 0.30.x / 0.32.x` → `cachetools>=4.2.2,<5.0.0`. `solana>=0.36.1` drops it, which requires `anchorpy>=0.21.0`.

Fix sketch: bump `plugins/aea-ledger-solana/setup.py` to `anchorpy>=0.21.0,<0.22.0`, `solana>=0.36.1,<1.0.0`, `solders>=0.21.0,<1.0.0`. Patch-bump plugin `2.2.1 → 2.2.2`. Audit plugin internals for solana-py 0.29 → 0.36 API drift. Downstream uncomment in `open-autonomy/pyproject.toml` is a second follow-up PR.

---

[#780]: https://github.com/valory-xyz/open-aea/issues/780
[#775]: https://github.com/valory-xyz/open-aea/issues/775
[#754]: https://github.com/valory-xyz/open-aea/issues/754
[#784]: https://github.com/valory-xyz/open-aea/pull/784
[#2479]: https://github.com/valory-xyz/open-autonomy/issues/2479
