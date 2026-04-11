# Repo Cleanup Candidates

Audit of items that could be removed or simplified to reduce repo surface area.

## Completed in this cleanup pass

### `scripts/check_pipfile_and_toxini.py` — already rolled into PR #871

Originally flagged as dead code referencing a non-existent `Pipfile`. PR #871 (merged) renamed and modernised this logic into `plugins/aea-ci-helpers/aea_ci_helpers/check_pyproject.py`, which reads `pyproject.toml` and is wired into the `aea-ci check-pyproject` command. The filesystem-level deletion landed as part of that PR; nothing further required. The original `scripts/check_pyproject_and_toxini.py` (an earlier replacement) was also removed in PR #871.

### Stale `tox.ini` envlist entries ✓ pruned

The envlist used `{plugins-,}py{3.10,3.10-cov,3.11,3.12,3.13,3.14,3.15}` plus a standalone `plugins_deps` entry. The expansion generated these entries which had no corresponding `[testenv:*]` sections:

- `py3.10-cov`, `plugins-py3.10-cov`
- `py3.15`, `plugins-py3.15`
- `plugins_deps`

(Earlier drafts of this doc incorrectly listed `packages-py*` entries — the envlist brace expansion was `{plugins-,}`, not `{packages-,}`.)

Verified nothing in `.github/`, `Makefile`, or `docs/` referenced any of these names before removal. The `packages-py3.10`…`packages-py3.14` sections exist but are intentionally not in `envlist` — they are invoked directly by CI via `tox -e packages-py3.10`, which remains valid.

### `PyNaCl` from `plugins/aea-ledger-solana/setup.py` ✓ removed

Earlier audit claimed PyNaCl was declared but never imported — that was wrong: the plugin source never imports it, but `tests/test_solana.py` used `nacl.signing.VerifyKey` 3× for Ed25519 signature verification in `test_sign_message`. Rewrote those call sites to use `cryptography.hazmat.primitives.asymmetric.ed25519.Ed25519PublicKey` (already a direct dep) and switched the bad-signature assertions from an exception-message string match to `pytest.raises(InvalidSignature)`. This also fixed a latent bug in the original test: the old `try: ... except Exception as e: assert ...` pattern would silently pass if the bad signature happened to verify.

### Unused scripts in `scripts/` ✓ all removed

All five scripts previously flagged (`deploy_to_registry.py`, `log_parser.py`, `parse_main_dependencies_from_lock.py`, `publish_packages_to_local_registry.py`, `spell-check.sh`) have been deleted. The first four moved into the new `aea-dev-helpers` plugin in `546de82c0` ("feat: create aea-dev-helpers plugin, migrate all scripts to plugins"); `log_parser.py` and `spell-check.sh` were deleted outright in `6e2397e6c` ("chore: migrate scripts to aea-ci-helpers, delete obsolete scripts").

### `libp2p_node` Go dependency bumps ✓ 14/14 actionable alerts closed

The Go `go.mod` in `packages/valory/connections/p2p_libp2p/libp2p_node/` was carrying 15 Dependabot alerts. Two commits on this branch resolved every one that has an upstream fix:

- `9a653ba72` — chore(libp2p_node): bump Go deps to close Dependabot security alerts
- `b5aeb6be3` — chore(libp2p_node): bump go-ethereum v1.14.11 → v1.17.2

Result: 14 of 15 alerts closed. Current `go.mod` is on `go 1.24.0`, `golang.org/x/crypto v0.45.0`, `github.com/ethereum/go-ethereum v1.17.2`, `btcd/btcec/v2 v2.3.4`, `btcd/btcutil v1.1.5`, `libp2p v0.33.2`, `libp2p-kad-dht v0.25.2`, `protobuf v1.36.11`. The migration required moving from `libp2p-core` (removed upstream) to `libp2p/core/*`, from `go-libp2p-circuit` (removed) to `circuit/v2`, and from the legacy `btcd` root + `btcutil` to the new modular `btcd/btcec/v2` + `btcd/btcutil`. 11 source files touched for import migrations + API fixes (`libp2p.New` no longer takes context, `peer.ID.Pretty()` → `String()`, btcec/v2 signatures no longer expose `R`/`S` fields — rewrote DER ↔ compact conversion to use `encoding/asn1`, `network.Stream` interface gained methods so mocks needed updating). Also fixed a pre-existing bug: `btcec.NewPrivateKey(elliptic.P256())` in `dhtpeer.go` was always wrong (btcec is secp256k1-only) — replaced with `ecdsa.GenerateKey(elliptic.P256(), rand.Reader)`.

**Remaining**: alert #108 (`github.com/libp2p/go-libp2p-kad-dht`, medium — Kademlia DHT content censorship). **No upstream fix exists**; tracked but not actionable.

### `libs/go/aealite` Go dependency bumps ✓ done, CI tests wired up

Done in a separate subagent pass after the libp2p_node bump. `libs/go/aealite/go.mod` was carrying the same class of stale deps as libp2p_node but was invisible to Dependabot because no `dependabot.yml` existed. Bumped the same target versions (`go 1.24`, `go-ethereum v1.17.2`, `x/crypto v0.45.0`, `btcec/v2`, `libp2p v0.33.2`, `protobuf v1.36.11`, `zerolog v1.32.0`). Also bumped `libs/go/aea_end2end` and `libs/go/aealite_agent_example` (which reference `aealite` via replace directives). Commits:

- `39d3b542c` chore(aealite): bump Go deps to modern versions matching libp2p_node
- `5671a710c` test(aealite): gate peer-dependent integration tests behind build tag
- `b94b1627f` docs(aealite): annotate intentional InsecureSkipVerify in ACN handshake
- `896e6ac4b` chore(aealite): bump Go deps in aea_end2end and aealite_agent_example
- `a7f5a7f03` ci: wire real Go build/vet/test into golang_checks, expand Dependabot

The `golang_checks` CI job was previously a no-op (checkout + setup-go, no test steps, `continue-on-error: True`). It now runs `go build ./... && go vet ./... && go test ./...` for all four Go modules (libp2p_node, aealite, aea_end2end, aealite_agent_example) on Ubuntu/macOS/Windows with Go 1.24. `continue-on-error: False`. `libs/go/aealite` unit tests (helpers, wallet, protocols) pass; the 2 peer-dependent integration tests (`TestAgent`, `TestP2PClientApiInit`) are gated behind `//go:build integration` and only run under `go test -tags integration`.

### `InsecureSkipVerify` in `libs/go/aealite/connections/tcpsocket.go` ✓ annotated

CodeQL flagged the `InsecureSkipVerify: true` setting in the ACN handshake code. This is intentional — the code does manual application-level signature verification of the peer certificate's public key against a pre-shared out-of-band peer public key, which is the correct ACN protocol pattern (mirrors the Python `p2p_libp2p_client/connection.py`). Added an 8-line inline comment explaining the design, `//nolint:gosec // G402 intentional: see comment above` suppressions, and `MinVersion: tls.VersionTLS12` as a belt-and-braces hardening. Behaviour unchanged.

### `.github/dependabot.yml` ✓ created

No Dependabot config existed — alerts were only being raised against `packages/valory/connections/p2p_libp2p/libp2p_node/go.mod` (auto-discovered). `libs/go/aealite`, `libs/go/aea_end2end`, and `libs/go/aealite_agent_example` were invisible to Dependabot. Created `.github/dependabot.yml` with explicit entries for all 4 Go modules plus `github-actions` and `pip`, all weekly. Closes the monitoring gap.

### `p2p_libp2p` connection fingerprint regen ✓ done

The libp2p_node source changes invalidated the embedded fingerprints in two connection packages. Regenerated via `tox -e lock-packages` in `d8559e768` + `2f3190519`:

- `valory/p2p_libp2p:0.1.0` → `bafybeictlungm37ohnn7ax6fsmgnze3ra7nc32prvrxktiaubfwi7tgbzy`
- `valory/test_libp2p:0.1.0` → new hash
- `docs/p2p-connection.md` and `docs/package_list.md` embedded hashes refreshed

Only these two packages needed regen — `p2p_libp2p_client` and `p2p_libp2p_mailbox` don't embed libp2p_node source and were unchanged.

### Circuit v2 relay routing parity ✓ restored

Both DHT relay tests (`TestRoutingDHTClientToDHTClient` and
`TestRoutingDHTClientToDHTClientIndirect`) now pass end-to-end on
libp2p v0.33, restoring full behavioural parity with the pre-bump v0.8
binary. Earlier in the session both were gated behind
`os.Getenv("RUN_CIRCUIT_V2_RELAY_TESTS")` while the migration was
incomplete; that gate has now been removed. Test runtimes after the
fix: direct topology 1.06s, indirect topology ~11s. Full
`dht/dhtpeer/` suite (excluding the long stress/ordering tests) is
green in 42s.

The migration required spelling out, on the v0.33 side, what
`libp2p.EnableRelay()` did implicitly in v0.8. Briefly:

- **dhtpeer.go (relay-side)**: `EnableRelayService()` +
  `ForceReachabilityPublic()` — the v2 relay only advertises the
  `/libp2p/circuit/relay/0.2.0/hop` protocol once AutoNAT confirms
  public reachability; forcing it skips the wait.
- **dhtclient.go (client-side)**: `EnableRelay()` +
  `ForceReachabilityPrivate()` +
  `EnableAutoRelayWithStaticRelays(bootstrapPeers)`. Without forcing
  private reachability auto-relay never starts (no listen addresses
  → AutoNAT can't determine reachability).
- **dhtclient.go::SetupDHTClient**: synchronous `waitForCircuitAddress`
  helper after bootstrap so the client doesn't expose itself to peers
  before its circuit address is in the host's address list.
- **dhtclient.go::newStreamLoopUntilTimeout**:
  `network.WithUseTransient(ctx, "circuit-relay routing")` — circuit-v2
  connections are tagged "transient" and `NewStream` refuses to use
  them by default in v0.33. Pre-bump this concept did not exist.
- **dhtclient.go::RouteEnvelope**: two-step Connect — try the
  source-relay path with a 5s timeout (fast same-relay path), then
  fall back to a peer-ID-only Connect so DHT-based peer routing can
  discover the target's actual `/p2p-circuit` address (announced by
  `EnableAutoRelayWithStaticRelays` and gossiped via Identify) and
  dial via the correct relay.

Every change has an inline comment explaining the v0.8 → v0.33 gap it
compensates for. The README in
`packages/valory/connections/p2p_libp2p/` carries the per-call-site
migration notes plus a wire-compat scenario matrix for mixed-version
deployments (the circuit-relay protocol IDs themselves changed
between v0.8 and v0.21 upstream, so a new node and an old node
cannot use each other as relays — direct peer-to-peer and delegate
paths are unaffected).

## Deferred / still open after this pass

Tracked here so the next person knows exactly what's left without re-walking the audit:

1. ~~**Finish libp2p_node circuit v2 migration.**~~ ✓ done — see "Circuit v2 relay routing parity ✓ restored" above. Both relay tests now pass on v0.33; full v0.8 routing parity is preserved (with the upstream wire-protocol break documented in the connection's README).

2. ~~**`libs/go/aea_end2end` Python↔Go harness modernization.**~~ ✓ done — `test_fipa_end2end.py` now passes end-to-end (`1 passed in 10.11s`), giving us a real Python AEA ↔ Go aealite wire-compat check running over a live libp2p ACN network. Together with the `dht/dhtpeer/` relay routing tests, this is the strongest validation we have for the libp2p_node bump.

   The harness was written against pre-bump `fetchai/p2p_libp2p:0.21.0`, when `fetchai` was the framework's `DEFAULT_LEDGER` and the connection only needed a single fetchai key for both the agent identity and the connection identity. Three breaking upstream changes had to be threaded through:

   1. **Package layout move**: `packages/fetchai/connections/p2p_libp2p` → `packages/valory/connections/p2p_libp2p`. The `_make_libp2p_connection` helper also relocated from `tests/conftest.py` to `packages/valory/connections/test_libp2p/tests/base.py`.
   2. **`DEFAULT_LEDGER` flipped**: `fetchai` → `ethereum`. So `cls.generate_private_key()` (no args) now creates `ethereum_private_key.txt`, and `aea get-address fetchai` fails because the buyer no longer has a fetchai key.
   3. **Multi-ledger connection requirements**: `valory/p2p_libp2p:0.1.0` now needs three keys: the main agent key (default ethereum), a `cosmos` key for the ACN node identity (`connection.yaml: ledger_id: cosmos`), and an `ethereum` key for the cert request (`cert_requests[0].ledger_id: ethereum`) — the latter two both added with `connection=True` so `aea issue-certificates` finds them.

   Fixes landed in `test_fipa_end2end.py`:
   - Import path migrations: `packages.fetchai.connections.p2p_libp2p` → `packages.valory.connections.p2p_libp2p`; `_make_libp2p_connection` from the new test_libp2p location.
   - `package_registry_src_rel` rebound to `Path(__file__).resolve().parent.parent.parent.parent / "packages"` so it doesn't resolve to `/Users/packages` when pytest is run from the repo root.
   - Connection public-id updated to `valory/p2p_libp2p:0.1.0` everywhere (including the `get-multiaddress` `-i` argument).
   - Three-key setup wired in: default-ledger key as agent identity AND cert signer (via `add_private_key(connection=True)`), plus a cosmos key for the ACN node identity (`add_private_key("cosmos", ..., connection=True)`).
   - `get-multiaddress` switched to `cosmos` ledger, `get-address` switched to `ethereum`.
   - Buyer's libp2p `local_uri` / `public_uri` / `delegate_uri` pinned to `127.0.0.1:9000` / `9000` / `11000` via `set_config` so they don't drift onto a port the seller-side connection_node will also try to bind.
   - Seller-side `_make_libp2p_connection` given explicit `port=12234, delegate_port=12235` (rather than the default `next(ports)` allocator that picks `10234`/`10235`, which can collide with leftover libp2p_node subprocesses from previous failed test runs).
   - `ENV_TEMPLATE`'s `AEA_P2P_DELEGATE_PORT` aligned to `12235` so the Go seller binary connects to the seller-side connection_node's delegate at the same port the connection_node is exposing.
   - Teardown's hardcoded `libp2p_node_10234.log` filename updated to `12234` and gated behind `if exists()` so a previous-run failure path doesn't mask the real test result on subsequent runs.

   **What the harness now exercises end-to-end**: Python AEA buyer (with libp2p_node binary on port 9000) → ACN routing → seller-side Python connection_node (libp2p_node binary on port 12234) → Go aealite seller binary (delegate-client to 12235) → FIPA dialogue (cfp / propose / accept / match_accept / inform) → end-of-protocol confirmation.

   **Currently runs locally only.** Wiring the test into CI as a Python integration job (alongside `golang_checks`, which currently only builds `aea_end2end` but doesn't run the Python harness) is a small follow-up.

3. **`ecdsa>=0.19.2` pin bump** for `aea-ledger-cosmos` (see the "ecdsa" section under "Dependabot alerts requiring action"). API compat verified locally; blocked on confirming downstream consumer compatibility before flipping the pin in 4 files.

4. **`requests` dev-group dep bump** to close alert #159. Recommendation: **bump, don't drop** — `requests` is a real runtime dep for `aea-ledger-{cosmos,ethereum,fetchai}` (already pinned in their own `setup.py`) and imported directly by tests. Dropping the dev-group entry would break `poetry install` without closing the alert. Bump the floor to `>=2.32.4,<3` (fix version for the `extract_zipped_paths` temp-file issue) in 4 places: `pyproject.toml:30`, `plugins/aea-ledger-cosmos/setup.py:47`, `plugins/aea-ledger-fetchai/setup.py:47`, `plugins/aea-ledger-ethereum/setup.py:46`. Deferred pending downstream-consumer compat check.

5. ~~**Plugin `install_requires` hygiene fixes**~~ ✓ done — all four categories:
   - **A:** added missing runtime deps to `aea-ci-helpers` (`pyyaml`), `aea-cli-benchmark` (`click`, `cosmpy`, `docker`), `aea-cli-ipfs` (`click`), and `aea-dev-helpers` (`gitpython`, `packaging`, `open-aea-cli-ipfs`).
   - **B:** removed redundant `web3>=7.0.0,<8` and `protobuf>=5,<7` from `aea-ledger-ethereum-hwi/setup.py` (neither is imported; `eth-account` transitively covers everything the HWI source touches).
   - **C:** added `extras_require={"test_tools": ["pytest", "docker==7.1.0"]}` to `aea-ledger-ethereum`, `aea-ledger-fetchai`, and `aea-cli-ipfs` (the last omits `docker`). Consumers who `import plugin.test_tools.*` now get a clean install path via `pip install plugin[test_tools]` instead of a silent `pytest` ImportError.
   - **D1:** swapped `pip._internal.commands.show.search_packages_info` for stdlib `importlib.metadata.distribution` in `aea-ci-helpers/check_imports.py`. No more pip private-API fragility.
   - **D2:** dropped `toml` entirely; `check_pyproject.py` and `check_dependencies.py` now use a conditional `tomllib` (stdlib 3.11+) / `tomli` (3.10 shim) pattern for reads and `tomli-w` for writes. `aea-ci-helpers/setup.py` install_requires now declares `tomli; python_version < "3.11"` and `tomli-w`. Dead `toml==0.10.2` pins removed from `pyproject.toml:65` dev group and from `tox.ini` `update-dependencies` + `check-dependencies` envs. Verified end-to-end via `aea-ci check-pyproject` and `aea-ci check-dependencies --check`.

6. ~~**Docs quickstart pipenv → poetry migration**~~ ✓ done — replaced `pipenv`/`Pipfile` instructions with `python -m venv` across `docs/quickstart.md`, `docs/raspberry-set-up.md`, `docs/http-echo-demo.md`, `docs/aev-echo-demo.md`. Chose `venv` over `poetry` for user-facing docs because (a) the rest of the quickstart is pip-based, (b) zero extra prerequisites, and (c) poetry is the contributor tool, not the user tool. `docs/upgrading.md:77` intentionally left untouched as a historic record.

7. ~~**`benchmark/` vs `plugins/aea-cli-benchmark/` consolidation**~~ ✓ done (variant of option 2). Deleted `benchmark/checks/` entirely (9 duplicated `check_*.py`, `run_benchmark.sh`, `run_benchmark_messages_mem.sh`, `utils.py`, `data/`) and `benchmark/run_mem_check_in_cloud.sh` (dead fetchai gcr image + pipenv). **Kept and fixed** `run_from_branch.sh` (venv + `aea benchmark reactive/proactive/multiagent_message_exchange`), `Dockerfile` (bookworm base, plain pip install, no pipenv/Pipfile wget), and `benchmark-deployment.yaml` (image bumped from EOL `python:3.10-buster` to `python:3.10-bookworm`). `benchmark/framework/` + `benchmark/cases/cpu_burn.py` preserved as teaching material for `docs/performance-benchmark.md`. Updated `benchmark/README.md` accordingly.

8. ~~**Docs staleness audit**~~ ✓ done — walked all 19 files flagged in the docs/ section (C). Fixed 9 with ground-truth-verified edits (CLI install names, command signatures, dead faucet link, stale `aea-config.yaml` / `skill.yaml` examples, `fetchai/p2p_libp2p*` → `valory/p2p_libp2p*`, `cert_requests` example from real connection.yaml, ledger-plugin list in `faq.md`); confirmed 10 evergreen and left untouched. See the expanded "C. Staleness audit" subsection below for the per-file breakdown.

## Likely removable

### `benchmark/` vs `plugins/aea-cli-benchmark/` ✓ consolidated

Done in commit `7593cce05` (variant of option 2, with the runners modernized instead of deleted). Summary:

**Deleted** (~2500 LOC of dead duplication + pipenv/fetchai-gcr ghosts):
- `benchmark/checks/` entirely (9 duplicated `check_*.py` mirroring the plugin's `case_*/case.py`, plus `utils.py`, `run_benchmark.sh`, `run_benchmark_messages_mem.sh`, `data/`).
- `benchmark/run_mem_check_in_cloud.sh` — referenced a dead `gcr.io/fetch-ai-sandbox` image + pipenv + the deleted `checks/` scripts.

**Rewritten for modern Poetry / plugin CLI:**
- `benchmark/run_from_branch.sh` — now creates a venv, installs `open-aea[all]` + `aea-cli-benchmark` + the 3 ledger plugins from source, and invokes `aea benchmark reactive/proactive/multiagent_message_exchange` directly. No more pipenv, no more nested shell runner.
- `benchmark/Dockerfile` — `python:3.10-bookworm` base, plain pip install, dropped the fetchai Pipfile wget and the alpine + gfortran + openblas pile.
- `benchmark/benchmark-deployment.yaml` — initContainer image bumped from EOL `python:3.10-buster` to `python:3.10-bookworm`.
- `benchmark/README.md` — invocation instructions reflect the new single-script flow.

**Kept as-is:**
- `benchmark/framework/` + `benchmark/cases/cpu_burn.py` — teaching material for `docs/performance-benchmark.md` against the in-house `BenchmarkControl` framework. No duplication with the plugin.

## Partially removable (incomplete Poetry migration)

### `setup.py`

Still needed because `release.yml` uses `python setup.py sdist bdist_wheel` to build distributions. Could be removed if the release workflow were migrated to use `python -m build` (which reads `pyproject.toml`).

### `setup.cfg`

Contains tool configurations for flake8, isort, mypy, darglint, and bdist_wheel. These could be consolidated into `pyproject.toml` `[tool.xxx]` sections, allowing removal of this file.

### `scripts/install.sh` and `scripts/install.ps1` ✓ kept, freshened

Decision: **keep.** These are the one-shot bootstrap installers linked from install docs; `aea-dev bump-version` already auto-updates the hardcoded `open-aea[all]==<version>` string on every release (see `plugins/aea-dev-helpers/aea_dev_helpers/bump_version.py:97-98`), so the version isn't drift-prone.

One real staleness fix landed alongside the keep decision: both scripts' Python version checks only accepted `3.10`/`3.11`, so users with `python3.12`/`3.13`/`3.14` (all supported by `pyproject.toml: python = ">=3.10,<3.15"`) would be rejected by their own install script. Bumped the regex in `install.sh:30` and `install.ps1:60` to accept the full `3.10–3.14` range and updated the user-facing error message in `install.sh:32`. The bootstrap-installer branch (when the user has no Python at all) still installs 3.10, which is fine — 3.10 is supported and keeping the target conservative avoids pinning a more recent patch URL I can't verify.

## Plugin `install_requires` hygiene ✓ done

All four categories completed in commits `901736ce0` (A) and `4e2d5b246` (B/C/D). Historical audit preserved below for context.

### A. Undeclared runtime deps — real install-breakage risk ✓ fixed

Plugins that imported packages not declared in their own `install_requires`, so a clean `pip install <plugin>` into an empty venv would `ImportError`:

| Plugin | Was missing | Fix |
|---|---|---|
| `aea-ci-helpers` | `pyyaml` | added `pyyaml>=6.0,<7` |
| `aea-cli-benchmark` | `click`, `cosmpy`, `docker` | added `click>=8.1.0,<8.4.0`, `cosmpy>=0.11.0,<0.12`, `docker==7.1.0` |
| `aea-cli-ipfs` | `click` | added `click>=8.1.0,<8.4.0` |
| `aea-dev-helpers` | `gitpython`, `packaging`, `open-aea-cli-ipfs` | added `gitpython>=3.1.37,<4`, `packaging`, `open-aea-cli-ipfs>=2.0.0,<3.0.0` |

Note on `click`: core `open-aea` only declares `click` in the `[cli]` extra, so plugins that import `click` must declare it themselves.

### B. Redundant declared deps ✓ removed

`aea-ledger-ethereum-hwi/setup.py` dropped `web3>=7.0.0,<8` and `protobuf>=5,<7`. Neither is imported by the plugin source; `eth-account` (still declared) transitively pulls in everything the HWI source actually touches (`eth_keys`, `eth_rlp`, `eth_typing`, `eth_utils`, `rlp`, `cytoolz`, `construct`, `hexbytes`).

### C. Test-only deps leaking into production packages ✓ fixed

`aea-ledger-ethereum`, `aea-ledger-fetchai`, and `aea-cli-ipfs` ship a `test_tools/` subpackage with top-level `import pytest`. Moved to `extras_require={"test_tools": ["pytest", "docker==7.1.0"]}` (the ipfs variant omits `docker`). Consumers who want the test helpers now `pip install plugin[test_tools]` and get a clean install path instead of a silent `ImportError` at module load.

Chose option 1 (extras_require) over lazy-import because `@pytest.fixture` decorators run at module import time — they cannot be moved inside function bodies.

### D. Antipatterns ✓ both fixed

- **D1:** `aea-ci-helpers/check_imports.py` — swapped `from pip._internal.commands.show import search_packages_info` for stdlib `importlib.metadata.distribution(name)`. No more pip private-API fragility across pip versions.
- **D2:** Dropped `toml` entirely. `check_pyproject.py` and `check_dependencies.py` now use a conditional `tomllib` (stdlib 3.11+) / `tomli` (3.10 back-compat shim) pattern for reads, and `tomli-w` for writes. `aea-ci-helpers/setup.py install_requires` declares `tomli; python_version < "3.11"` and `tomli-w`. Dead `toml==0.10.2` pins also removed from `pyproject.toml` dev group and the `update-dependencies` + `check-dependencies` tox envs. Verified end-to-end via `aea-ci check-pyproject` and `aea-ci check-dependencies --check`.

## `docs/` and `examples/` cleanup

Audit of the `docs/` tree (75 markdown files) and `examples/` tree (5 subdirs). Findings grouped by priority.

### A. High priority — user-facing regressions from the Poetry migration

1. **Pipfile / pipenv references in user-facing tutorials.** The quickstart and demo docs still tell new users to `pipenv --python 3.10 && pipenv shell`, but the repo migrated to Poetry and the Pipfile is gone. This breaks the first-run experience.
   - `docs/quickstart.md:107-118,415` — mentions `pipenv` 5 times
   - `docs/raspberry-set-up.md:37-46` — 3 mentions
   - `docs/upgrading.md`, `docs/aev-echo-demo.md`, `docs/http-echo-demo.md` — 1-2 mentions each
   - **Fix:** replace with Poetry (`poetry install --with dev; poetry shell`) or a plain `python -m venv` equivalent.

2. ~~**`docs/release-process.md` references three deleted scripts.**~~ ✓ done — `bump_aea_version.py`/`update_plugin_versions.py` invocations now use `aea-dev bump-version`/`aea-dev update-plugin-versions` from the `open-aea-dev-helpers` plugin; the `spell-check.sh` wrapper call was dropped and the existing `pylint --disable all --enable spelling` invocation retained (it was the real check).

3. ~~**`docs/release-process.md` nav status**~~ ✓ done — intentionally kept out of `mkdocs.yml` (maintainer workflow, not framework user documentation). `CONTRIBUTING.md` now has a short "Cutting a release" section linking to `docs/release-process.md` so maintainers can find it. While editing `CONTRIBUTING.md`, also swapped the stale `pipenv shell` reference for `poetry shell` to match the actual `make new_env` flow.

### B. Dead or near-dead files — candidates for deletion

1. ~~**`examples/ml_ex/`**~~ ✓ done — deleted the stale Keras `model.json` and the `--scan-path examples/ml_ex` entries from `tox.ini` tomte copyright scanners. No other references in the repo.

2. **`examples/aealite_go/`** — tied to `libs/go/aealite`. Since `libs/go/` is now being actively maintained (deps bumped, CI tests wired, Dependabot covered), this example is also kept. Has a minimal README; a follow-up could expand it into a working tutorial that exercises the updated `aealite` API.

3. ~~**`docs/known-limits.md`**~~ ✓ done — stub deleted and nav entry removed. The 3 bullets were redistributed to their natural homes rather than merged into `limits.md` (which is organized around design decisions, not runtime caveats): the two AEABuilder consistency caveats moved into the `AEABuilder` class docstring in `aea/aea_builder.py`; the skill lifecycle ordering note moved into `docs/skill.md` under the "Independence of skills" section.

4. ~~**`docs/notes.md`**~~ ✓ done — deleted outright. 4-line threading trivia, already orphaned from the nav.

### C. Staleness audit — ~19 docs untouched since 2020–2023 ✓ done

Walked all 19 files and made targeted fixes where ground truth was out of sync with the current framework. Evergreen files confirmed left untouched.

**CLI bucket — fixed:**
- `cli-how-to.md`: `pip install aea[cli]`/`aea[all]` → `open-aea[cli]`/`open-aea[all]` throughout (the old PyPI name hasn't worked in years; this was actively breaking first-run installs).
- `cli-commands.md`: `run` description dropped "on the Fetch.ai network"; `generate-wealth` signature updated from `[ledger_id]` to `[ledger_id] [url]` to match the real CLI which requires a URL.
- `wealth.md`: rewrote to drop the dead `faucet.dimensions.network` Fetch.AI-era link and the misleading "Simply generate wealth via the CLI" claim. Now directs users to choose a testnet faucet for their target network and shows the real `aea generate-wealth <type> <url>` signature.
- `scaffolding.md`: already done in the D1 commit (`b6f82d9fd`).

**Framework concepts bucket — fixed:**
- `logging.md`: replaced the entire stale `aea-config.yaml` example (`author: fetchai`, `aea_version: 0.6.0`, `default_ledger: fetchai`, `fetchai/stub`, `fetchai/error`) with a real one captured from `aea create my_aea` in a clean env (`author: your_author_handle`, `aea_version: '>=2.0.0, <3.0.0'`, `default_ledger: ethereum`, empty connections/skills/contracts, `open-aea-ledger-ethereum` dep).
- `skill.md`: skill.yaml example updated to match the real `packages/fetchai/skills/echo/skill.yaml` shape — fixed `authors` → `author`, added the missing `type: skill` and `aea_version` fields, bumped the shown version to the actual `0.19.0`.
- `acn.md`: removed the "p2p_libp2p_mailbox connection is not available yet" note — that connection has existed at `packages/valory/connections/p2p_libp2p_mailbox/` for a while — and added it to the trust/security connection list.
- `modes.md`, `message-routing.md`: confirmed accurate against current runtime behavior; left untouched.

**Identity / trust bucket — fixed:**
- `por.md`: swapped `fetchai/p2p_libp2p*` → `valory/p2p_libp2p*`; replaced the `cert_requests` example (stale fetchai ledger, 2023/2024 dates in the past) with the literal block from `packages/valory/connections/p2p_libp2p/connection.yaml` (`ledger_id: ethereum`, `public_key: cosmos`, `not_before: '2026-01-01'`, `not_after: '2027-01-01'`); updated the explanatory narrative to match.
- `identity.md`, `trust.md`, `language-agnostic-definition.md`: confirmed evergreen; left untouched. `language-agnostic-definition.md` is deliberately the interop spec for third-party AEA implementations, and the protobuf schemas shown still match the real `envelope.proto`.

**Meta bucket — fixed:**
- `faq.md`: "native support for three different networks: Fetch.ai, Ethereum and Cosmos" → updated to reflect the real current plugin set (Ethereum incl. Flashbots/HWI, Cosmos, Fetch.ai, Solana). Reworded the "private keys stored in .txt files. This is temporary and will be improved soon" entry, since that has been the behavior for years — pointer added to the `-p`/`--password` flag and the security notes.
- `vision.md`, `app-areas.md`, `demos.md`, `security.md`, `design-principles.md`: confirmed accurate / evergreen; left untouched.

### D. Minor cosmetic items

1. ~~**`docs/scaffolding.md`**~~ ✓ done — `aea create my_aea --author "fetchai"` replaced with `"your_author_handle"`. Safe because this flag sets the user's own author handle; it is not a reference to any published package.

2. **Fetchai-weighted tutorial doc set** (`quickstart.md`, `echo_demo.md`, `http-echo-demo.md`, `aev-echo-demo.md`) — **deferred, not cleanup scope**. Every `fetchai/*` identifier in these docs is the functional public_id of a real package living on disk under `packages/fetchai/` (e.g. `fetchai/echo:0.19.0`, `fetchai/http_echo:0.20.0`, `fetchai/stub:0.21.0`, `fetchai/default:1.0.0` protocol). The author field is fixed at publish time and baked into the IPFS hashes users download. Rebasing these onto a `valory/*` or `open_aea/*` vendor would require moving 4+ packages on disk, regenerating every fingerprint and hash, re-publishing to the public IPFS registry (breaking existing downstream hashes cached by users), and parallel updating every test and config reference. That is a strategic registry migration, not a tutorial cleanup. Left as-is.

### Order of operations ✓ executed

All docs/examples cleanup items landed across commits `710805517` (A1 pipenv → venv), `d11044e56` (A2 release-process + B1/B3/B4 deletions + known-limits bullets redistributed), `b6f82d9fd` (A3 CONTRIBUTING.md link + D1 scaffolding author placeholder), and `08886f8f1` (C staleness audit). D2 documented as deferred (strategic registry migration, not cleanup scope).

## Dependabot alerts requiring action

### Go: `packages/valory/connections/p2p_libp2p/libp2p_node/go.mod` — 1 remaining, unfixable

Down from 15 open alerts to 1 after the two Go-dep bump commits on this branch. See the "libp2p_node Go dependency bumps" entry in the "Completed" section above. The remaining alert is #108 (`github.com/libp2p/go-libp2p-kad-dht`, medium — Kademlia DHT content censorship abuse) which has **no upstream fix** and is tracked as not-actionable. The Dependabot UI may still show some already-closed alerts until the next rescan; they will auto-close when the bumped branch reaches the default branch.

### Python: `plugins/aea-ledger-cosmos/setup.py` — one open `ecdsa` alert

Current state on this branch: pinned `ecdsa>=0.15,<0.17.0` (resolving to `0.16.1`). Dependabot alerts against `ecdsa`:

| # | GHSA | State | Severity | Fixed in |
|---|---|---|---|---|
| #147 | `GHSA-9f5j-8jwj-x28g` — DoS via improper DER length validation | **open** | medium | **`0.19.2`** |
| #146 | same | fixed | medium | `0.19.2` |
| #160 | same | dismissed | medium | `0.19.2` |
| #156 | `GHSA-wj6h-64fc-37mp` — Minerva timing attack on P-256 | dismissed | high | **none** — the `ecdsa` project explicitly states side-channel resistance is out of scope |

**Only #147 is actionable**, and a pin bump to `ecdsa>=0.19.2` fixes it.

**Why not switch to `coincurve`:** initially considered, but the ROI is poor:
- `coincurve` is **not** transitively present via `web3 → eth-account → eth-keys` — modern `eth-keys` made `coincurve` optional and ships a pure-Python fallback. So switching would add a new explicit binary dep.
- The only unfixable alert (#156 Minerva) would remain dismissed either way; side-channel risk is orthogonal to library choice.
- The call sites are non-trivial: cosmos uses `sign_deterministic(sigencode=sigencode_string_canonize)` + `VerifyingKey.from_public_key_recovery`; `p2p_libp2p_{client,mailbox}` use `from_der` + DER-signature verify; `scripts/acn/run_acn_node_standalone.py` uses `SigningKey.from_string` for config validation. Each would need per-site rewrite with byte-level compat testing for cosmos on-chain signatures.
- A plain pin bump is mechanically trivial, closes the only actionable alert, and preserves all signature byte formats.

**Action — pin bump to `ecdsa>=0.19.2,<0.20`**, gated on downstream compatibility:

- [x] API compatibility verified locally (`sign_deterministic`, `sigencode_string_canonize`, `VerifyingKey.from_public_key_recovery`, `from_der`, `verify(sigdecode=sigdecode_der)` all byte-compatible between `0.16.1` and `0.19.2`; 64-byte sig + 2 recovered keys match).
- [ ] Confirm downstream consumers (Valory agents, olas-protocol-resolver, etc.) are compatible with a cosmos plugin that requires `ecdsa>=0.19.2` before flipping the pin.
- [ ] Bump pins in 4 locations: `plugins/aea-ledger-cosmos/setup.py:42`, `tox.ini:21`, `tox.ini:40`, `pyproject.toml:36`.

### Python: `requests` (1 alert)

- #159 (medium): Insecure temp file reuse in `extract_zipped_paths()`. PR #867 ("chore: remove requests from base deps") **merged 2026-04-10**, removing `requests` from the core install requirements. The alert is still open because `requests = ">=2.20.0,<3"` remains as a **dev dependency** in `pyproject.toml:30` and therefore shows up in `poetry.lock`. The alert will close only when either the dev-group pin is bumped to a fixed version, or `requests` is dropped from the dev group entirely.

## Confirmed keep

### `*-image/` directories (deploy, develop, docs, user)

All four are published to Docker Hub via `release.yml`. Actively maintained.

### `plugins/aea-cli-benchmark/`

Published to PyPI on every release. Provides the user-facing `aea benchmark` CLI command. This is the supported, modern path.

### `examples/tac_deploy/`, `examples/http_ex/`, `examples/protocol_specification_ex/`

Referenced in framework documentation (`docs/deployment.md`, `docs/protocol-generator.md`, `docs/http-connection-and-skill.md`).

## Core dependencies analysis

After the dependency cleanup work (PRs #858–#867), core deps are:

- `packaging>=22.0,<27`
- `protobuf>=5,<7`
- `pyyaml>=6.0.1,<7`

All three have **zero transitive dependencies** and are maintained by reputable upstreams. Considered and rejected for further inlining:

### `pyyaml` (~5,890 LOC, keep)

Used across framework config loading (`aea/helpers/yaml_utils.py`, `aea/configurations/loader.py`, `aea/cli/*`, package YAML files). Replacing would require:

- Option 1: Write a minimal YAML parser (~500–1000 LOC for the subset open-aea uses: block mappings, sequences, scalars, comments, multi-doc, env var interpolation). Several days of work with real risk of subtle config-parsing bugs.
- Option 2: Migrate configs to JSON/TOML — breaking change for every user of the framework and every downstream package. Not acceptable.

**Verdict**: keep. Zero transitive deps, single well-maintained file format, no realistic alternative. YAML is the *lingua franca* for aea package configs and users expect it.

### `packaging` (~5,853 LOC total, ~1,930 LOC actually used, keep)

Used by `aea/configurations/data_types.py`, `aea/configurations/base.py`, `aea/configurations/pypi.py`, `aea/helpers/base.py`, and a few CLI files for:

- `Version(string)` — PEP 440 version parsing
- `Version.major`, `.minor`, `.micro`, `.base_version`, `.is_prerelease`, `.is_devrelease`, `.is_postrelease`
- Version comparison operators
- `SpecifierSet(string)` — parse `>=1.0,<2.0` style specs
- `SpecifierSet.__contains__(version)` — version matching
- `Specifier` — individual `>=1.0` specs with `.operator` and `.version` properties
- `operator.and_` for combining SpecifierSets (intersection)

Of the ~5,853 LOC in the library, we only need `version.py` (792), `specifiers.py` (1,068), and shared `_structures.py` (69) — roughly 1,930 LOC. The rest (`tags`, `markers`, `metadata`, `pylock`, `requirements`, `_musllinux`, `_manylinux`, `_elffile`) is irrelevant.

A custom implementation would be ~400–600 LOC, but PEP 440 has non-obvious edge cases:

- Release-level comparison: `1.0a1 < 1.0b1 < 1.0rc1 < 1.0`
- `1.0.post1 > 1.0` but `1.0.dev1 < 1.0`
- `1.0 == 1.0.0 == 1.0.0.0` (trailing-zero normalisation)
- Local versions (`1.0+local`)
- Compatible release operator `~=` expansion
- Wildcard matching `1.0.*`

**Verdict**: keep. Zero transitive deps, maintained by PyPA, and getting PEP 440 comparison semantics wrong would silently corrupt agent dependency resolution. The custom-impl risk/benefit is unfavourable compared to pyyaml.

### `protobuf` (~15,332 LOC pure Python + C extension, keep)

Unlike `pyyaml` and `packaging`, `protobuf` is not just a library — it's the foundational wire format for the entire AEA framework. There are **15 generated `*_pb2.py` files** across `aea/` and `packages/` (one per protocol and message type), all of which `import google.protobuf.descriptor`, `google.protobuf.message`, and `google.protobuf.reflection`. Removing the runtime would break every protocol definition.

**Why it can't reasonably be replaced:**

1. **It's a binary wire format, not text.** Protobuf uses tag-length-value encoding with varints, zig-zag for signed ints, bit-packing, length-delimited fields. Wire-level compatibility matters — two agents on different machines need to decode the same bytes.

2. **The generated code assumes a runtime.** `protoc --python_out=.` produces code that instantiates `_descriptor.Descriptor`, `_descriptor.FieldDescriptor`, and uses `_reflection.GeneratedProtocolMessageType` as the metaclass. You can't drop in a replacement — you'd need to reimplement the entire descriptor/reflection/message-metaclass machinery.

3. **Cross-language compatibility is the point.** AEA agents send envelopes serialized with protobuf. Go peers (in `libs/go/`, `packages/valory/connections/p2p_libp2p/libp2p_node/`) decode those bytes using Go's protobuf library. The value of protobuf is that it's a *standard* — Google/PyPA/Go/C++/Rust all agree on the wire format. Swapping the Python side for a custom serializer would break Python ↔ Go interop.

4. **Scale of reimplementation.** The pure-Python runtime is ~15,332 LOC across 55 files, plus a C extension for speed. It implements: wire format encoder/decoder (varints, tag packing, length-delimited); runtime descriptor system; message metaclass generating getters/setters/serializers per field; text and JSON formats; well-known types (Any/Timestamp/Duration); extension registry; oneof; maps; enums; proto2 vs proto3 semantics. You can't "inline a subset" — the generated `_pb2.py` files call into specific APIs that pull in most of the rest of the library.

5. **Zero transitive deps** (same clean profile as `pyyaml` and `packaging`). `pip show protobuf` has an empty `Requires:` line.

**Verdict**: keep. This is foundational infrastructure — the literal wire format between agents. Removing it would mean either rewriting every protocol in a different serialization format (breaking all existing agents and all downstream packages) or reimplementing protobuf itself. Neither is worth it.

#### Could protobuf be decoupled as a transport layer from the protocols?

Separate question from "can we remove it": **can protobuf be treated as a pluggable codec rather than being hardcoded into every protocol?** The framework already has the abstraction in place:

```python
# aea/protocols/base.py
class Encoder(ABC):
    @staticmethod
    @abstractmethod
    def encode(msg: Message) -> bytes: ...

class Decoder(ABC):
    @staticmethod
    @abstractmethod
    def decode(obj: bytes) -> Message: ...

class Serializer(Encoder, Decoder, ABC): ...

# aea/mail/base.py
class EnvelopeSerializer(ABC): ...
class ProtobufEnvelopeSerializer(EnvelopeSerializer): ...
```

So at the **interface level**, the framework is already decoupled. What's tightly coupled is the **implementation**:

- `aea/mail/base.py` imports `aea.mail.base_pb2` directly and the only shipped envelope serializer is `ProtobufEnvelopeSerializer`.
- Every shipped protocol (`default`, `fipa`, `signing`, `acn`, `http`, `ledger_api`, `contract_api`, `tac`, `oef_search`, `state_update`, `t_protocol`) has a `serialization.py` that imports `aea.mail.base_pb2` + `<protocol>_pb2` directly and calls `SerializeToString()` / `ParseFromString()`.
- The protocol generator (`aea/protocols/generator/`) emits protobuf-based code.

**Four decoupling options, from least to most invasive:**

##### Option 1: Lazy protobuf import (trivial, ~20 LOC)

Move `from aea.mail import base_pb2` inside `ProtobufEnvelopeSerializer.__init__` (or into the encode/decode methods) so importing the framework doesn't transitively import protobuf. Useful for tooling/lightweight consumers that never actually serialize envelopes.

- **Dep impact**: none. protobuf is still required at runtime.
- **Effort**: trivial.
- **Value**: low — just delays the import by microseconds.

##### Option 2: Pluggable envelope serializer (~100 LOC, bounded refactor)

Thread the `EnvelopeSerializer` choice through `Multiplexer` construction so consumers can swap `ProtobufEnvelopeSerializer` for a JSON/MessagePack/custom alternative. Ship `ProtobufEnvelopeSerializer` in an `aea.mail.codecs.protobuf` submodule that only loads when explicitly selected.

- **Dep impact**: protobuf *could* become optional (an extras dep) IF combined with Option 3 below — otherwise still required at runtime because every shipped protocol uses it internally.
- **Effort**: medium. Touches `Multiplexer`, `base.py`, p2p connection code. Doesn't require rewriting any protocols.
- **Value**: architectural polish. Enables experimental alternative codecs for same-language deployments. Keeps protobuf as the default.

##### Option 3: Pure-Python message classes + codec adapter layer (huge refactor)

Refactor every shipped protocol so that:

- `schema.py` — pure Python dataclass with type hints (no pb2 dependency)
- `message.py` — uses the dataclass, no pb2 import
- `codecs/protobuf.py` — adapter converting dataclass ↔ pb2 at serialize/deserialize time only
- `codecs/json.py` — optional alternative codec

The protocol author would write **schema + message logic in pure Python**, and the codec layer would handle wire-format translation. Protobuf would become a plugin rather than a runtime dependency of every protocol.

- **Dep impact**: protobuf could move to `aea[protobuf]` extras. Core framework becomes protobuf-free.
- **Effort**: **huge.** Every shipped protocol needs its message class rewritten. Every downstream package using these protocols needs verification. The protocol generator in `aea/protocols/generator/` needs to emit dataclass-based code instead of pb2-based code. Protocol tests need updating.
- **Risk**: **wire compatibility.** The whole point of protobuf is a stable binary wire format. If we write our own dataclass → protobuf translation, we have to reproduce the protobuf wire format byte-for-byte, or existing agents silently stop interop'ing with upgraded ones. Extremely easy to get wrong.
- **Value**: conceptual cleanliness + optional protobuf. But protobuf is still required for Python ↔ Go interop via `p2p_libp2p`, so the dep reduction only helps consumers who don't use p2p.

##### Option 4: Replace protobuf with a different wire format entirely

E.g., MessagePack or CBOR (both have small pure-Python implementations). Would also require updating the Go `libp2p_node/` side to decode the new format. Breaks wire compatibility with every existing agent and every downstream package built against the current protocols.

- **Not feasible.** Fragments the network and breaks cross-language interop.

**Comparison with prior inlining decisions:**

| Dep | Transitive deps | Our usage | Maintenance risk | Decision |
|-----|-----------------|-----------|------------------|----------|
| `requests` | 5+ | thin wrapper over urllib | high — deprecated patterns | **removed** ✓ |
| `ipfshttpclient` | 12+ | alpha-quality abandoned | high | **inlined** ✓ |
| `jsonschema` | 4 | Draft-04 validation | medium | **inlined** ✓ |
| `python-dotenv` | 0 | simple env file parsing | low | **inlined** ✓ |
| `semver` | 0 | version comparison | low | **replaced with packaging** ✓ |
| `protobuf` | **0** | **core wire format, cross-language, generated code** | **low** | **keep** |

Unlike all the deps we successfully removed/inlined, protobuf has:

- **Zero transitive dependencies** (same as `pyyaml` and `packaging`)
- A narrow, well-defined API surface we interact with (`SerializeToString` / `ParseFromString` / field setters)
- Zero realistic alternatives that preserve cross-language wire compatibility
- A reputable upstream (Google) that ships security fixes promptly

**Recommendation:**

- **Option 1 (lazy import)** is cheap and clearly positive — do it if/when convenient. It's a ~20 LOC change that delays protobuf loading without risk.
- **Option 2 (pluggable envelope serializer)** is only worth doing if there's a concrete product requirement (e.g., "we need a non-protobuf codec for an edge device that can't run the protobuf runtime"). Pure architectural polish otherwise.
- **Options 3 and 4** are not worth doing. The ROI is bad: thousands of LOC of refactor, real risk of silent wire-compat bugs breaking Python↔Go interop, and ongoing maintenance burden of a custom dataclass↔protobuf translation layer — all to remove a single dependency that is already clean (zero transitive deps, well maintained, standard format).

**Bottom line:** the dependency tree is as lean as it can reasonably get. Core deps are `packaging`, `protobuf`, `pyyaml` — all three with zero transitive deps, all three essential in ways that make replacement uneconomical. Further work on dependency cleanup should focus on removing *optional* deps from plugins, not on further reducing the core three.

## Plugin crypto dependency analysis

The ledger plugins (`aea-ledger-cosmos`, `aea-ledger-ethereum`, `aea-ledger-ethereum-flashbots`, `aea-ledger-ethereum-hwi`, `aea-ledger-fetchai`, `aea-ledger-solana`) each pull in a different set of crypto libraries. This section audits whether a more unified stack is possible.

### Current direct crypto deps per plugin

| Plugin | Direct crypto/crypto-adjacent deps | Notes |
|--------|-----------------------------------|-------|
| `cosmos` | `ecdsa>=0.15,<0.17`, `bech32`, `pycryptodome`, `cosmpy`, `requests` | 1 open alert on `ecdsa`: #147 (DER DoS, medium, fixed in 0.19.2). #156 (Minerva timing attack, high) is dismissed upstream — side-channel resistance is explicitly out of scope for the `ecdsa` project. See the "ecdsa pin-bump plan" section below. |
| `ethereum` | `web3>=7.0.0,<8`, `eth-account>=0.13.0,<0.14`, `requests` | web3 is heavy but canonical |
| `fetchai` | inherits `cosmos`, plus `requests` | same alerts propagate |
| `ethereum-hwi` | inherits `ethereum`, plus `ledgerwallet`, `construct`, `protobuf` | hardware wallet niche |
| `solana` | `cryptography`, `solders`, `solana`, `anchorpy` | `PyNaCl` removed — see "Completed" section above |
| `ethereum-flashbots` | inherits `ethereum`, plus `open-aea-flashbots` | — |

### Is there a single "unified" crypto library?

**No.** Research across the Python crypto ecosystem (`cryptography` / pyca, `pycryptodome`, `coincurve` / libsecp256k1, `PyNaCl` / libsodium, `ecdsa` pure-Python, `eth-keys`) turns up no library that covers every operation the plugins need. The coverage matrix:

| Library | secp256k1 sign/verify | RFC 6979 | Pubkey recovery | Ed25519 | Keccak256 | AES-GCM | Fernet | scrypt | SHA/RIPEMD |
|---------|-----------------------|----------|-----------------|---------|-----------|---------|--------|---------|------------|
| `cryptography` (pyca) | ✓ | ✗ | ✗ | ✓ | ✗ | ✓ | ✓ | ✓ | ✓ |
| `pycryptodome` | ✗ (NIST P-curves only) | n/a | ✗ | ✓ | ✓ | ✓ | ✗ | ✓ | ✓ |
| `coincurve` (libsecp256k1) | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `ecdsa` (pure Python) | ✓ | ✓ | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `PyNaCl` (libsodium) | ✗ | n/a | ✗ | ✓ | ✗ | (XSalsa20) | ✗ | ✗ | SHA only |

Three hard gaps prevent single-library consolidation:

1. **secp256k1 public key recovery from signature** — only in `coincurve`, `eth-keys`, `ecdsa`. Needed by `aea/helpers/acn/agent_record.py:97` (ACN agent record verification), `plugins/aea-ledger-cosmos/.../cosmos.py:386`, and `plugins/aea-ledger-ethereum/.../ethereum.py:876`. Not available in `cryptography` (OpenSSL's ECDSA API doesn't expose the recovery ID; pyca maintainers have repeatedly declined to add it).

2. **secp256k1 RFC 6979 deterministic ECDSA** — only in `coincurve`, `ecdsa`, `pycryptodome` (for NIST curves only, **not secp256k1**; verified locally via `DSS.new` raising `ValueError: Unsupported curve 'secp256k1'`). Needed by cosmos for deterministic transaction signing.

3. **Keccak256** (not SHA3-256 — the padding byte differs) — only in `pycryptodome`, `eth-hash`, `pysha3`. Needed for Ethereum address derivation.

**Important correction**: early research suggested `pycryptodome + coincurve` might be a 2-library unification, and that `cryptography` could be the base. Local verification showed `pycryptodome` does **not** support secp256k1 ECDSA (only NIST curves), and `cryptography` cannot do Keccak256, RFC 6979, or pubkey recovery — three hard gaps with no workaround. `cryptography` is the **wrong** base choice for a multi-chain SDK that includes Ethereum.

### Minimum viable crypto stack

The thinnest 2-library pair that covers all 10 operations is:

**`pycryptodome` + `coincurve`**

- `pycryptodome`: Ed25519, Keccak256, AES-GCM/EAX, scrypt, PBKDF2, SHA-2, RIPEMD-160 (and Fernet-compatible can be built on top in ~30 LOC)
- `coincurve`: secp256k1 sign, verify, RFC 6979, public key recovery (wraps bitcoin-core's `libsecp256k1` C library — same library used by `eth-keys`)

Note that **if you install `aea-ledger-ethereum`, you already transitively get both `pycryptodome` and `coincurve`** via the chain `web3 → eth-account → eth-keys → coincurve` and `eth-account → eth-keyfile → pycryptodome`. So standardizing on this pair adds zero new transitive deps for users who install ethereum, and only costs standalone cosmos/solana users a C extension (which has prebuilt wheels for all major platforms).

### Concrete consolidation opportunities

| # | Action | Effort | Impact | Risk | Recommendation |
|---|--------|--------|--------|------|----------------|
| 1 | ~~Remove `PyNaCl` from `plugins/aea-ledger-solana/setup.py`~~ | — | — | — | ✓ **Done** (see "Completed" section — required rewriting `test_solana.py::test_sign_message` from `nacl.VerifyKey` to `cryptography.Ed25519PublicKey`) |
| 2 | Replace `ecdsa` with `coincurve` in `plugins/aea-ledger-cosmos/aea_ledger_cosmos/cosmos.py` and `packages/valory/connections/p2p_libp2p_client/connection.py`, `packages/valory/connections/p2p_libp2p_mailbox/connection.py` | medium (~50 LOC per site + real-chain testing) | closes the one actionable alert (#147 DER DoS, medium), faster sign/verify (C vs pure Python), aligns with ethereum's transitive stack. Minerva (#156) is dismissed and would remain dismissed under `coincurve` too (side-channel risk is orthogonal to library choice). | medium — signature format compatibility must be preserved exactly (canonical DER for ACN, sigencode_string_canonize for cosmos) or nodes reject transactions | **Superseded by pin bump** — the `ecdsa>=0.19.2,<0.20` plan in the ecdsa pin-bump section closes #147 with a one-line change and preserves byte formats. Only revisit if a second actionable alert surfaces. |
| 3 | ~~Create `aea.helpers.keyfile_crypto` shared module~~ | — | — | — | **Rejected — see note below** |
| 4 | Migrate solana from `cryptography.fernet` to `pycryptodome`; drop `cryptography` from solana's direct deps | small code change (~30 LOC) | solana drops `cryptography` direct dep | **high — breaks existing encrypted solana keyfiles without a migration path** | **Defer** until a broader keyfile migration is planned |
| 5 | Investigate replacing `anchorpy` with inlined helpers (two narrow use sites: `ACCOUNT_DISCRIMINATOR_SIZE` constant + `_decode_idl_account` function) | medium | solana drops `anchorpy` dep | medium — need to verify edge cases in IDL decoding | **Worth investigating separately** |

**Note on the rejected "shared keyfile helper" idea:** An earlier draft proposed creating `aea.helpers.keyfile_crypto` to de-duplicate the private-key encryption logic between cosmos (pycryptodome AES-EAX + scrypt) and solana (cryptography Fernet). **This was rejected on reflection** because any helper that lives in `aea/helpers/` and uses AES would force a crypto library back into core deps — Python stdlib has `hashlib.scrypt` (3.6+) but **no AES primitives**, so symmetric encryption requires an external dep. The options were:

- Put the helper in `aea/helpers/` → pulls `pycryptodome` into core deps (regression from the "3 core deps with zero transitive deps" bar we set)
- Put the helper in one plugin and import from another → introduces cross-plugin dependencies that don't currently exist
- Lazy-import the crypto library inside helper functions → works technically but introduces a "soft dep" with fragile ergonomics (and `pycryptodome` still has to be installed somewhere)
- Create a new `aea-crypto-utils` plugin for ~80 LOC → overengineered

None of these tradeoffs are worth the ~100 LOC of duplication between cosmos and solana's existing, well-tested implementations. The duplication is small, contained, and already works. **Leave the two implementations in their respective plugins.**

### Can the ethereum plugin be reduced to just `cryptography` + `pycryptodome`?

**No.** This is a natural follow-up question but the answer is a clear no, for three reasons:

1. **`cryptography` is the wrong base.** It can't do Keccak256, RFC 6979, or secp256k1 public key recovery — three things Ethereum requires. You'd need `pycryptodome + coincurve` instead, and both of those are already pulled in transitively by `eth-account` anyway.

2. **`web3.py` and `eth-account` are not thin wrappers — they are the canonical Python implementations of the Ethereum protocol.** They're maintained by the Ethereum Foundation's ecosystem and track protocol evolution (new EIPs, new transaction types, new L2 quirks). Unlike `requests` (thin wrapper over urllib) or `ipfshttpclient` (500-line alpha wrapper), they are the shape of the problem.

3. **Scale of reimplementation is roughly 2500-3500 LOC of security-critical, spec-compliance code**, broken down as:

   **Replacing `web3`** (~1500-2000 LOC):
   - JSON-RPC client with provider abstraction (~300 LOC)
   - Contract ABI encoder/decoder — `uint<N>`/`int<N>`/`bytes<N>`/`bytes`/`string`/tuples/dynamic arrays/fixed arrays (~500-1000 LOC; this is what `eth-abi` provides and it's what makes web3 hard to replace)
   - Event decoding + topic filter encoding + indexed-param handling (~200-300 LOC)
   - Gas pricing strategies including EIP-1559 max-fee logic and chain-specific overrides for L1/L2 (~150 LOC)
   - PoA middleware for Gnosis / BSC / Polygon / other `extraData`-based chains (~50 LOC)
   - Revert reason decoding (ABI-encoded `Error(string)` / custom error selectors) (~100 LOC)
   - Address checksum (EIP-55) (~30 LOC)
   - Filter management with pagination (`get_logs` batching) (~100 LOC)
   - Type conversions, caching, middleware builder, error types (~150 LOC)

   **Replacing `eth-account`** (~1000-1500 LOC):
   - Keystore v3 format (PBKDF2 or scrypt + AES-CTR + MAC) (~200 LOC)
   - Legacy transaction signing with EIP-155 chain-ID binding (~150 LOC)
   - EIP-1559 typed transaction 0x02 (~150 LOC)
   - EIP-2930 access list transaction 0x01 (~100 LOC)
   - EIP-4844 blob transaction 0x03 (+ KZG commitment setup) (~200 LOC)
   - EIP-191 `personal_sign` (~50 LOC)
   - EIP-712 typed data signing (~400 LOC — this is the hardest)
   - Public key ↔ address derivation via Keccak256 (~30 LOC)
   - Internal helpers, `SignedTransaction`, `LocalAccount`, hash computation (~100 LOC)

**Why the ROI is unfavourable:**

| Aspect | `requests` replacement | `web3` / `eth-account` replacement |
|--------|------------------------|------------------------------------|
| LOC we'd write | ~240 | ~2500–3500 |
| Spec stability | stable (HTTP/1.1) | **moving target** (new EIPs every cycle) |
| Consequence of a 1-byte bug | malformed request | **silently sign the wrong transaction → user loses funds** |
| Maintenance burden | low (stdlib urllib is stable) | **ongoing** — track every new EIP, new L2, new transaction type |
| Benefit | removed bloated wrapper with 5 transitive deps | removed the canonical Ethereum libs, gaining... what exactly? |
| Canonical upstream alternative | stdlib `urllib.request` | **none** — web3.py and eth-account *are* the canonical Python Ethereum stack |

**Rule of thumb** from the prior cleanup work: we removed dependencies that were thin wrappers over stdlib (`requests`, `python-dotenv`), abandoned alpha-quality packages (`ipfshttpclient`), or had simple, frozen specifications (`jsonschema` Draft-04, `semver`). None of those criteria apply to `web3` or `eth-account`. They are the problem, not a wrapper around it.

**Recommendation: do not attempt to replace `web3` or `eth-account`.** The ethereum plugin's dep tree is inherently large because Ethereum itself is complex. Further plugin-level cleanup should focus on:

- Actions 1–3 above (remove unused `PyNaCl`, replace `ecdsa` with `coincurve`, create shared keyfile helper)
- Auditing transitive deps of `web3`/`eth-account` for anything we don't actually use (e.g., `aiohttp` if we drop `AsyncWeb3`, `websockets` if we never use websocket providers)
- Possibly splitting `aea-ledger-ethereum` into `[core]` (signing only: `eth-account` + stdlib RPC) vs `[rpc]` (full web3) extras — but this breaks virtually every existing user who interacts with smart contracts

### Bottom line for plugin crypto

The plugin crypto footprint *can* be reduced, but only modestly and only with targeted work. The theoretical "unified crypto library" doesn't exist — `pycryptodome + coincurve` is the minimum viable pair and both are already pulled in transitively by ethereum. The realistic gains are:

- **-1 dep** from removing unused `PyNaCl` from solana (trivial, zero risk)
- **-1 dep** from replacing `ecdsa` with `coincurve` in cosmos + p2p_libp2p connections (closes 2 Dependabot alerts, medium effort)
- Eventually **-1 dep** from migrating solana off `cryptography.fernet` (breaking change, defer)

Total achievable reduction: **2 unique deps near-term, possibly 3 long-term**. The ethereum plugin itself stays at `web3 + eth-account + requests` — that's the correct shape for a full-featured Ethereum SDK.

**Explicitly not doing**: creating a shared keyfile-encryption helper in `aea/helpers/`. Any such helper would force a crypto library (pycryptodome or similar) back into core deps because Python stdlib has no AES primitives. The ~100 LOC of duplication between cosmos's `DataEncrypt` and solana's `Fernet` wrapper is the correct tradeoff — small, contained, working — and preserves the "3 core deps with zero transitive deps" invariant.
