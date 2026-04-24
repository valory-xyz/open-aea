This page provides some tips on how to upgrade AEA projects between different versions of the AEA framework. For full release notes check the <a href="https://github.com/valory-xyz/open-aea/tags" target="_blank">AEA repo</a>.

The primary tool for upgrading AEA projects is the `aea upgrade` command in the <a href="../cli-commands/">CLI</a>.

Below we describe the additional manual steps required to upgrade between different versions:


# Open AEA

### Upgrade guide

## `v2.2.1` to `v2.2.2`

This is a non-breaking patch release. The core framework is unchanged; the notes below concern the Ethereum and Solana ledger plugins.

### `open-aea-ledger-ethereum` — chain-aware gas defaults

`get_default_gas_strategy(chain_id)` now applies a unified `CHAIN_EIP1559_OVERRIDES` map, so the `eip1559` and `eip1559_polygon` fallback values differ per chain:

- Optimism / Base / Mode / Fraxtal — 5 gwei `maxFeePerGas`, 3 gwei tip.
- Arbitrum One — 2 gwei `maxFeePerGas`, 1 gwei tip (above the 0.1 gwei floor).
- Polygon — 6000 gwei `maxFeePerGas`, 30 gwei tip, `min_allowed_tip` 30 gwei, `max_gas_fast` 10000.
- Celo — 50 gwei `maxFeePerGas`, 25 gwei tip, `min_allowed_tip` 25 gwei.
- Gnosis — 5 gwei `maxFeePerGas`, 1 gwei tip, `min_allowed_tip` 1 gwei.
- Every other chain inherits `DEFAULT_FALLBACK_ESTIMATE` unchanged.

The new defaults apply whether the ledger is built via `make_ledger_api('ethereum', chain_id=...)` directly or through the `valory/ledger` connection. Anything explicitly passed in `gas_price_strategies` keeps precedence, so existing overrides continue to win. If your project shipped per-chain overrides *because* the old defaults were off, you can drop them — but audit transactions on the chains above after the bump to confirm the new numbers fit your budget.

The `valory/ledger` connection's `connection.yaml` was also re-aligned to the same per-chain values and gained a Polygon-specific `eip1559_polygon` block so tuned values apply on the default path.

### `open-aea-ledger-ethereum` — `get_l1_data_fee` now safe on every chain

`EthereumApi.get_l1_data_fee` used to be OP-stack only and would fail silently on other L2s. It now dispatches by `chain_id`: OP-stack (Optimism, Base, Mode, Fraxtal) via `GasPriceOracle`, Arbitrum Nitro (Arbitrum One, Arbitrum Nova) via the `NodeInterface` precompile, and `0` on any other chain. Callers that need the L1 data fee (e.g. drain-address budgeting) can invoke the helper unconditionally.

### `open-aea-ledger-ethereum` — Polygon gas station URL

`POLYGON_GAS_ENDPOINT` was switched from the deprecated `gasstation-mainnet.matic.network/v2` to the canonical `gasstation.polygon.technology/v2`. Callers of the `eip1559_polygon` strategy benefit automatically; no action required unless you proxy / allow-list the old host.

### `open-aea-ledger-solana` — bumped to solana-py 0.33.x

The plugin now pins `solana>=0.33.0,<0.34.0`, `solders>=0.21.0,<0.22.0`, `anchorpy>=0.20.0,<0.21.0`. This removes the transitive `cachetools<5` pin that `solana-py` 0.29–0.32 carried, so projects that need `cachetools>=7` (for example `tomte[tox]==0.6.5 → tox 4.46`) unblock.

`solana.blockhash.BlockhashCache` was removed upstream in 0.33.0; the plugin now ships a minimal TTL cache locally under the same import path so the public import surface is preserved. Downstream code that imports `BlockhashCache` from `aea_ledger_solana` continues to work. If you import it directly from `solana.blockhash`, switch to the plugin's re-export.

### `open-aea-ledger-ethereum-hwi` — orphaned `construct` cap dropped

The `construct<=2.10.61` pin was removed from the plugin's `install_requires`, `pyproject.toml`, and `tox.ini`. It had no current justification and conflicted with the solana plugin's resolution path. If you mirrored the pin in your own project, you can drop it.

### Concrete upgrade steps

- `pip install --upgrade "open-aea[all]==2.2.2"` (and the same `2.2.2` pin for any `open-aea-*` plugin you use).
- `aea --version` should report `2.2.2`.
- If you ship custom Ethereum gas overrides for Optimism / Arbitrum / Polygon / Celo / Gnosis, re-verify them against the new plugin defaults and drop any that are now redundant.
- If you import from `solana.blockhash` directly, switch to importing `BlockhashCache` from `aea_ledger_solana`.

## `v2.2.0` to `v2.2.1`

This is a non-breaking patch release. The core framework is unchanged and the last published `open-aea-ledger-ethereum-flashbots==2.2.0` wheel continues to install against this core; the notes below are only relevant if you want to drop that plugin from your project.

### `open-aea-ledger-ethereum-flashbots` no longer built here

The `aea-ledger-ethereum-flashbots` plugin has been removed from this repository — it was unmaintained and its source tree is no longer shipped alongside the rest of `open-aea`. The `2.2.0` wheel remains on PyPI; nothing breaks for existing consumers.

If you want to migrate off the plugin:

- Remove the `open-aea-ledger-ethereum-flashbots` pin from your dependency files.
- Drop any `ethereum_flashbots` section from the `valory/ledger` connection config (the `config.ledger_apis.ethereum_flashbots` block is no longer part of the shipped `connection.yaml` — use plain `ethereum` instead).
- Remove any `--collect-all aea_ledger_ethereum_flashbots` / `--hidden-import aea_ledger_ethereum_flashbots` flags from PyInstaller invocations.

If you still need flashbots submission, keep the existing pin or bundle the functionality into your own fork / plugin.

### Concrete upgrade steps

- `pip install --upgrade "open-aea[all]==2.2.1"` (and the same `2.2.1` pin for any `open-aea-*` plugin you use).
- `aea --version` should report `2.2.1`.

## `v2.1.0` to `v2.2.0`

This release removes several core dependencies and replaces them with inlined stdlib-based implementations. Plugins and downstream projects that relied on these packages being transitively available must now declare them explicitly.

### Core dependencies removed

The following packages are no longer installed by `open-aea`:

- `requests` -- plugins that use `requests` (e.g. `open-aea-ledger-cosmos`, `open-aea-ledger-ethereum`) already declare it in their own `install_requires`; if your code imports `requests` directly, add it to your own dependencies.
- `ipfshttpclient` -- replaced by an inlined IPFS HTTP client in `aea.helpers.ipfs`.
- `jsonschema` -- replaced by an inlined JSON Schema Draft-04 validator in `aea.helpers.jsonschema`.
- `python-dotenv` -- replaced by an enhanced stdlib-based env file parser in `aea.helpers.env_vars`.
- `semver` -- replaced by strict PEP 440 version parsing via `packaging`.
- `morphys` -- removed; functionality inlined.
- `ecdsa` -- removed from base deps; inlined secp256k1 validation in `aea.helpers.multiformat`. Plugins that use `ecdsa` (e.g. `open-aea-ledger-cosmos`) declare it themselves.
- `base58`, `multibase`, `multicodec`, `pymultihash` -- replaced by inlined multiformat helpers in `aea.helpers.multiformat`.

### New plugins

- `open-aea-ci-helpers` (`aea-ci` CLI) -- 8 CI automation commands previously in `scripts/`.
- `open-aea-dev-helpers` (`aea-dev` CLI) -- 7 release/dev tool commands previously in `scripts/`.

Install them with:
```bash
pip install open-aea-ci-helpers open-aea-dev-helpers
```

### Scripts removed

12 Python scripts have been deleted from `scripts/` and migrated to the `aea-ci` and `aea-dev` plugin CLIs, or to `tomte`. If you invoked any of these scripts directly, switch to the corresponding CLI command:

- `scripts/check_copyright.py` -> `tomte check-copyright`
- `scripts/check_doc_links.py` -> `tomte check-doc-links`
- `scripts/freeze_dependencies.py` -> `tomte freeze-dependencies`
- Other scripts -> `aea-ci <command>` or `aea-dev <command>`

### Tooling migration

- **Pipenv replaced by Poetry**: delete `Pipfile` / `Pipfile.lock` and use `pyproject.toml` + `poetry.lock`. Run `poetry install` to set up your environment.
- **tomte bumped to 0.6.5**: update your tomte pin from `0.6.1` to `0.6.5`.

### Concrete upgrade steps

1. Upgrade:
    - `pip install --upgrade "open-aea[all]==2.2.0"`
2. Audit your imports for any of the removed packages listed above and add explicit dependencies where needed.
3. If using Pipenv, migrate to Poetry:
    - `poetry init` (or adopt the upstream `pyproject.toml` as a template)
    - `poetry install`
4. Replace any direct `scripts/` invocations with `aea-ci`, `aea-dev`, or `tomte` CLI commands.
5. Verify:
    - `aea --version` should report `2.2.0`
    - `python -c "from aea.helpers.ipfs.base import IPFSHashOnly; print('OK')"` -- confirms inlined IPFS client works
    - `python -c "from aea.helpers.jsonschema import validate; print('OK')"` -- confirms inlined JSON Schema validator works

## `v2.0.8` to `v2.1.0`

- Python support is now `3.10-3.14` (previously `3.10-3.11`).
- Regenerate your environment and lock files when upgrading, as several toolchain and runtime dependencies were bumped to support newer Python versions.

Main dependency updates to account for:

- `tomte: 0.4.0 -> 0.6.1`
- `click: >=8.1.0,<8.3.0 -> >=8.1.0,<8.4.0`
- `pytest: >=7.0.0,<8.0.0 -> >=8.2,<10`
- `packaging: >=23.1,<24.0 -> ==26`
- `protobuf: >=4.21.6,<4.25.0 -> >=5,<6`
- `requests: ==2.28.1 -> ==2.32.5`
- `openapi-core: 0.15.0 -> 0.22.0`
- `openapi-spec-validator: >=0.4.0,<0.5.0 -> >=0.7.0,<0.8.0`
- `docker: 4.2.0 -> 7.1.0`
- `hypothesis: 6.21.6 -> 6.151.9`
- `cosmpy: ==0.9.2 -> >=0.11.0,<0.12`

Exact APIs/functions to check:

### 1) Click `flag_value` default handling

If your downstream CLI uses Click options with `flag_value`, audit these exact patterns against Open AEA fixes:

- `aea/cli/utils/click_utils.py::registry_flag`
- `aea/cli/utils/click_utils.py::remote_registry_flag`
- `aea/cli/packages.py::sync`
- `aea/cli/upgrade.py::upgrade`
- `scripts/update_package_versions.py` options `--update-minor` / `--update-patch`

Required behaviour:

- Do **not** rely on decorator order to select defaults when multiple flags write to the same parameter.
- Use explicit normalization in code for unset values (e.g. `if sync_type is None: sync_type = SyncTypes.THIRD_PARTY`).
- Ensure upgrade command handlers consume a single `registry: str` mode rather than split boolean flags (`local` / `remote`).

### 2) Python 3.13/3.14 asyncio/multiprocessing compatibility

Audit downstream code for these exact anti-patterns and replacements:

- `multiprocessing.Manager()` without explicit context on Python 3.14+.
  - Required fix pattern: use `multiprocessing.get_context("spawn").Manager()` where process-manager context must be controlled.
- Accessing private queue loop internals (e.g. `queue._loop`).
  - Required fix pattern: store/use explicit event loop references instead of private attributes.
- Removed/unsupported asyncio APIs in modern Python:
  - `asyncio.StreamReader(loop=...)`
  - `asyncio.ensure_future(..., loop=...)`
  - unconditional `asyncio.get_child_watcher()` / child-watcher usage on Python 3.14+
- Ready-awaitable internals relying on module-level coroutine/future objects.
  - Required fix pattern: use a lightweight awaitable object/factory that is loop-safe across Python 3.10-3.14.

### 3) Plugin dependency compatibility (Ethereum + Flashbots)

If you install both plugins, verify dependency constraints in your lock/constraints files:

- The Flashbots plugin package must be compatible with the same 2.1.x line of the Ethereum plugin package.
- Reject locks where Flashbots still constrains Ethereum to `<2.1.0`.

Concrete verification commands to run after upgrade:

1. Upgrade and reinstall:
    - `pip install --upgrade "open-aea==2.1.0"`
    - or for pre-release validation: `pip install --upgrade "open-aea==2.1.0rc6"`
2. Re-lock dependencies:
    - `pipenv lock` (or your equivalent lock workflow)
3. Verify CLI default routing behaviour:
    - `aea packages sync` (must default to third-party sync mode)
    - `aea packages sync --third-party`
    - `aea packages sync --dev`
    - `aea packages sync --all`
4. Verify interpreter matrix:
    - run your tests on Python `3.10` and `3.14`
5. Verify plugin resolution when Flashbots is used:
    - install both `open-aea-ledger-ethereum` and `open-aea-ledger-ethereum-flashbots` in a clean environment and ensure dependency resolution succeeds.

Known caveat:

- Historical installer scripts may still contain hard-coded checks/messages for Python `3.10/3.11`. Treat package metadata and release notes as the source of truth for supported runtime versions.

### API compatibility notes

- CLI/API-surface changes:
  - `aea/cli/utils/click_utils.py::password_option` now always prompts on `-p` and supports `AEA_PASSWORD` for `--password`.

- Side-effect risk to audit in downstream code:
  - `aea/helpers/async_utils.py::Runnable.wait_completed` internals changed to use a lightweight ready-awaitable for loop safety on Python 3.14; callers that relied on strict `Future` type checks should switch to awaitability checks instead.

## `v2.0.7` to `v2.0.8`

- No backwards incompatible changes

## `v2.0.6` to `v2.0.7`

- No backwards incompatible changes

## `v2.0.5` to `v2.0.6`

- No backwards incompatible changes

## `v2.0.4` to `v2.0.5`

- No backwards incompatible changes

## `v2.0.3` to `v2.0.4`

- No backwards incompatible changes

## `v2.0.2` to `v2.0.3`

- No backwards incompatible changes

## `v2.0.1` to `v2.0.2`

- No backwards incompatible changes

## `v2.0.0` to `v2.0.1`

- No backwards incompatible changes

## `v1.65.0` to `v2.0.0`

- No longer supports Python 3.8 and 3.9.
- `get_metavar` now requires a new parameter, `ctx: Context`
- `aea` and its subcommands that expect some arguments (for example `aea`, `aea ipfs`, etc.), when used without any arguments will now finish with exit code 2 instead of 0, and print their usage help in `stderr`.

## `v1.64.0` to `v1.65.0`

- No backwards incompatible changes

## `v1.63.0` to `v1.64.0`

- No backwards incompatible changes

## `v1.62.0` to `v1.63.0`

- No backwards incompatible changes

## `v1.61.0` to `v1.62.0`

- If `EthereumApi` is used for chains other than Gnosis then `min_allowed_tip` must be set to `1` through `gas_price_strategies` parameter. The default value is only suitable for Gnosis.

## `v1.60.0` to `v1.61.0`

- No backwards incompatible changes

## `v1.59.0` to `v1.60.0`

- No backwards incompatible changes

## `v1.58.0` to `v1.59.0`

- No backwards incompatible changes

## `v1.57.0` to `v1.58.0`

- No backwards incompatible changes

## `v1.56.0` to `v1.57.0`

- No backwards incompatible changes

## `v1.55.0` to `v1.56.0`

- The `priority_fee_estimation_trigger` has been removed from the `eip1559` configuration of the ledger.
- The `default_priority_fee` is now optional. 
  If it is set to `None`, dynamic pricing will be applied. 
  Otherwise, the specified value will be used.

## `v1.54.0` to `v1.55.0`

- No backwards incompatible changes

## `v1.53.0` to `v1.54.0`

- No backwards incompatible changes

## `v1.52.0` to `v1.53.0`

- No backwards incompatible changes

## `v1.51.0` to `v1.52.0`

This release contains updated version range for several dependencies so please update you environments with following dependency versions

- `psutil>=5.7.0,<6.0.0`
- `bech32>=1.2.0,<2`
- `PyNaCl>=1.5.0,<2`
- `click>=8.1.0,<9`
- `pyyaml>=6.0.1,<9`
- `requests>=2.28.1,<3`

## `v1.50.0` to `v1.51.0`

- No backwards incompatible changes

## `v1.49.0` to `v1.50.0`

- No backwards incompatible changes

## `v1.48.0.post1` to `v1.49.0`

- No backwards incompatible changes

## `v1.48.0` to `v1.48.0.post1`

- No backwards incompatible changes

## `v1.47.0` to `v1.48.0`

- No backwards incompatible changes

## `v1.46.0` to `v1.47.0`

The `send_signed_transaction` method implementation has been updated to follow the ledger plugin pattern, which means it will return the transaction digest, not the transaction receipt. To retrieve the transaction receipt use the `get_transaction_receipt` method.

## `v1.45.0` to `v1.46.0`

- No backwards incompatible changes
 
## `v1.44.0` to `v1.45.0`

- No backwards incompatible changes
 
## `v1.43.0.post2` to `v1.44.0`

- No backwards incompatible changes
  
## `v1.43.0.post1` to `v1.43.0.post2`

- No backwards incompatible changes

## `v1.43.0` to `v1.43.0.post1`

- No backwards incompatible changes

## `v1.42.0` to `v1.43.0`

- No backwards incompatible changes

## `v1.41.0.post1` to `v1.42.0`

- No backwards incompatible changes

## `v1.41.0` to `v1.41.0.post1`

- No backwards incompatible changes

## `v1.41.0` to `v1.41.0.post1`

- No backwards incompatible changes

## `v1.40.0` to `v1.41.0`

- The way the dependencies will be selected for installation when running `aea install` has changed. Before this version, the versions were being merging all of the versions for a python package and using the most compatible version specifier possible. With this release, this behaviour will be replaced by overriding the dependencies in the following order `extra dependencies provided by flag > agent > skill > connection > contract > protocol` what this means is, let's say you have 3 packages with a same python package as a dependency

* protocol package with `protobuf>1.0.0`
* connection package with `protobuf==1.0.0`
* skill package with `protobuf>=1.0.0,<2.0.0`

`protobuf>=1.0.0,<2.0.0` will be used for installation since skill has higher priority over protocol and connection packages.

## `v1.39.0.post1` to `v1.40.0`

- `open-aea-web3` has been replaced with `web3py`
- `protobuf` has been bumped to `protobuf>=4.21.6,<5.0.0`, this means you will have to bump your protocol generator to `v24.3` and generate your protocol packages again.
- Because of the protobuf version bump hardware wallet plugin might now work as expected, so please export `PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION="python"` to use the hardware wallet without any issues
- The `valory/open-aea-user` image will use Python 3.11 as default interpreter for running AEAs

## `v1.39.0` to `v1.39.0.post1`

- No backwards incompatible changes

## `v1.38.0` to `v1.39.0`

- No backwards incompatible changes

## `v1.37.0` to `v1.38.0`

- `web3py` has been replaced with `open-aea-web3` and we forked this from `web3py@v6.0.0`, that means the method names will use the `snake_case` and the `camelCase` naming has been deprecated
- `apduboy` has been deprecated as a dependency
- `flashbots` has been replaced with `open-aea-flashbots`
- Support for `Python 3.7` has been deprecated

## `v1.36.0` to `v1.37.0`

- No backwards incompatible changes

## `v1.35.0` to `v1.36.0`

- No backwards incompatible changes
  
## `v1.34.0` to `v1.35.0`

- No backwards incompatible changes
  
## `v1.33.0` to `v1.34.0`

- No backwards incompatible changes

## `v1.32.0` to `v1.33.0`

- No backwards incompatible changes

## `v1.31.0` to `v1.32.0`

- No backwards incompatible changes

You will have to generate the protocols again since protocol generator will use `double` to represent float values.

## `v1.30.0` to `v1.31.0`

- No backwards incompatible changes

**Note** The `Ethereum Flashbots` ledger plugin and `Solana` ledger plugin are only supported on Python 3.10 or greater.

## `v1.29.0` to `v1.30.0`

- No backwards incompatible changes

## `v1.28.0.post1` to `v1.29.0`

- No backwards incompatible changes
  
## `v1.28.0` to `v1.28.0.post1`

- No backwards incompatible changes

## `v1.27.0` to `v1.28.0`

One breaking change

- The public id format now requires the author name and the package name to be in snake case format

### Upgrade guide

## `v1.26.0` to `v1.27.0`

Multiple small backwards incompatible changes:
- `BaseContractTestCase` no longer sets a default `path_to_contract` and `ledger_identifier`. The user is expected to set these and an exception is thrown if classes are defined without these.
- `BaseContractTestCase` had wrongly defined `setup`. This is now changed to `setup_class`.
- `BaseSkillTestCase` no longer sets a default `path_to_skill`. The user is expected to set this and an exception is thrown if classes are defined without this.
- Comparison operators were fixed for multiple custom classes. Some edge cases will behave differently. Consult <a href="https://github.com/valory-xyz/open-aea/pull/428" target="_blank">#428</a> and related PRs.

Plugins from previous versions are not compatible anymore.

## `v1.25.0` to `v1.26.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.24.0` to `v1.25.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

The usage of `aea hash all` command has been deprecated and will be removed on `v2.0.0`, use `aea packages lock` command to perform hash updates for package dependencies.

## `v1.23.0` to `v1.24.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.22.0` to `v1.23.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.


This release introduces a new format for `packages.json` file, the older version is still supported but will be deprecated on `v2.0.0` so make sure to update your projects to use the new format.

## `v1.21.0` to `v1.22.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.20.0` to `v1.21.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.19.0` to `v1.20.0`


No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.18.0` to `v1.19.0`

- Deprecated the usage of `hashes.csv` and replaces it with `packages.json`, which is maintained by `aea packages lock`
- `--check` flag is deprecated from `aea hash all`, from now package consistencies can be verified by `aea packages lock --check`
- When running `init` if no registry flags provided, `local` will be used as the default registry and `IPFS` as the default remote registry

Plugins from previous versions are not compatible anymore.

## `v1.17.0` to `v1.18.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.16.0` to `v1.17.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.15.0` to `v1.16.0`

- A typo change, now import `from aea.helpers.dependency_tree import DependencyTree` rather than `from aea.helpers.dependency_tree import DependecyTree`.
- The global configuration file for the `aea` CLI has a breaking change. Please remove `~/.aea/cli_config.yaml` and rerun `autonomy init --remote`.

Plugins from previous versions are not compatible anymore.

## `v1.14.0` to `v1.15.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.13.0` to `v1.14.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.12.0` to `v1.13.0`

This releases introduces the usage of CID v1 IPFS hashes. We still support CID v0 hashes, but it is advisable to switch to CID v1 hashes.

Plugins from previous versions are not compatible anymore.

## `v1.11.0` to `v1.12.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.10.0` to `v1.11.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.9.0` to `v1.10.0`

Python 3.6 no longer supported

Plugins from previous versions are not compatible anymore.

## `v1.8.0` to `v1.9.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.7.0` to `1.8.0`

This release introduces a new format for `PublicId` parameter which allows users to use IPFS hashes as a part of the `PublicId` which may lead to some unexpected behaviours or bugs.

Previous implementation of `PublicId` used `author/package:version` format, The new implementation uses `author/package:version:hash`

This release also fixes the hash inconsistency by using wrapper hashes to represent packages.

Plugins from previous versions are not compatible anymore.

## `v1.6.0` to `v1.7.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.5.0` to `v1.6.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.4.0` to `v1.5.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.3.0` to `v1.4.0`

No backwards incompatible changes.

Plugins from previous versions are not compatible anymore.

## `v1.2.0` to `v1.3.0`

No backwards incompatible changes.

The `open-aea-ledger-ethereum` plugin now supports EIP1559 based gas estimation.

## `v1.1.0` to `v1.2.0`

No backwards incompatible changes.

The `open-aea-ledger-ethereum` plugin now supports EIP1159-style transactions.

## `aea==v1.1.0` to `open-aea==v1.1.0`

Backwards incompatible changes:

- removal of the GOP decision maker handler. However, via the configuration option of the decision maker handler this can be simply added as a standalone file.

- conversion of plugins due to their dependency on `aea`. Simply replace `aea-ledger-fetchai` with `open-aea-ledger-fetchai` etc.

Legacy packages can be used in open AEA too!

# Legacy AEA

## `v1.0.2` to `v1.1.0`

No backwards incompatible changes.

We advise everyone to upgrade their `fetchai` packages and plugins to get the latest fixes.

## `v1.0.1` to `v1.0.2`

No backwards incompatible changes.

We advise everyone to upgrade their `fetchai` packages and plugins to get the latest fixes.

## `v1.0.0` to `v1.0.1`

No backwards incompatible changes.

We advise everyone to upgrade their `fetchai` packages to get the latest fixes.

## `v1.0.0rc2` to `v1.0.0`

No backwards incompatible changes to component development.

We advise everyone to upgrade to `v1` as soon as possible. When upgrading from versions below `v1.0.0rc1` first upgrade to the first release candidate, then to `v1`.

## `v1.0.0rc1` to `v1.0.0rc2`

No backwards incompatible changes to component development.

Various configuration changes introduced in `v1.0.0rc1` are now enforced strictly.

## `v0.11.1` to `v1.0.0rc1`

No backwards incompatible changes to component development.

The `aea-config.yaml` now requires the field `required_ledgers` which must specify all ledgers for which private keys are required to run the agent. Please add it to your project.

The `registry_path` field has been removed from the `aea-config.yaml`. Please remove it from your project.

All packages provided by author `fetchai` must be upgraded.

## `v0.11.0` to `v0.11.1`

No backwards incompatible changes.

## `v0.10.1` to `v0.11.0`

Take special care when upgrading to `v0.11.0`. We introduced several breaking changes in preparation for `v1`!

### CLI GUI

We removed the CLI GUI. It was not used by anyone as far as we know and needs to be significantly improved. Soon we will release the AEA Manager App to make up for this.

### Message routing

Routing has been completely revised and simplified. The new message routing logic is described <a href="../message-routing/">here</a>.

When upgrading take the following steps:

- For agent-to-agent communication: ensure the default routing and default connection are correctly defined and that the dialogues used specify the agent's address as the `self_address`. This is most likely already the case. Only in some edge cases will you need to use an `EnvelopeContext` to target a connection different from the one specified in the `default_routing` map.

- For component-to-component communication: there is now only one single way to route component to component (skill to skill, skill to connection, connection to skill) messages, this is by specifying the component id in string form in the `sender`/`to` field. The `EnvelopeContext` can no longer be used, messages are routed based on their target (`to` field). Ensure that dialogues in skills set the `skill_id` as the `self_address` (in connections they need to set the `connection_id`).

### Agent configuration and ledger plugins

Agent configuration files have a new optional field, `dependencies`,  analogous to `dependencies` field in other AEA packages. The default value is the empty object `{}`. The field will be made mandatory in the next release.

Crypto modules have been extracted and released as independent plug-ins, released on PyPI. In particular:

- Fetch.ai crypto classes have been released in the `aea-ledger-fetchai` package;
- Ethereum crypto classes have been released in the `aea-ledger-ethereum` package;
- Cosmos crypto classes have been released in the `aea-ledger-cosmos` package.

If an AEA project, or an AEA package, makes use of crypto functionalities, it will be needed to add the above packages as PyPI dependencies with version specifiers ranging from the latest minor and the latest minor + 1 (excluded). E.g. if the latest version if `0.1.0`, the version specifier should be `<0.2.0,>=0.1.0`:
```yaml
dependencies:
  aea-ledger-cosmos:
    version: <3.0.0,>=2.0.0
  aea-ledger-ethereum:
    version: <3.0.0,>=2.0.0
  aea-ledger-fetchai:
    version: <3.0.0,>=2.0.0
```
The version specifier sets are important, as these plug-ins, at version `0.1.0`, depend on a specific range of the `aea` package.

Then, running `aea install` inside the AEA project should install them in the current Python environment.

For more, read the <a href="../ledger-integration">guide on ledger plugins</a>.

## `v0.10.0` to `v0.10.1`

No backwards incompatible changes for skill and connection development.

## `v0.9.2` to `v0.10.0`

Skill development sees no backward incompatible changes.

Connection development requires updating the keyword arguments of the constructor: the new `data_dir` argument must be defined.

Protocol specifications now need to contain a `protocol_specification_id` in addition to the public id. The `protocol_specification_id` is used for identifying Envelopes during transport. By being able to set the id independently of the protocol id, backwards compatibility in the specification (and therefore wire format) can be maintained even when the Python implementation changes.

Please update to the latest packages by running `aea upgrade` and then re-generating your own protocols.

## `v0.9.1` to `v0.9.2`

No backwards incompatible changes for skill and connection development.

## `v0.9.0` to `v0.9.1`

No backwards incompatible changes for skill and connection development.

## `v0.8.0` to `v0.9.0`

This release introduces <a href="../por">proof of representation</a> in the ACN. You will need to upgrade to the latest `fetchai/p2p_libp2p` or `fetchai/p2p_libp2p_client` connection and then use two key pairs, one for your AEA's decision maker and one for the connection.

Please update to the latest packages by running `aea upgrade`.

## `v0.7.5` to `v0.8.0`

Minimal backwards incompatible changes for skill and connection development:

- The semantics of the `<`, `<=`, `>` and `>=` relations in `ConstraintTypes` are simplified.
- Protocols now need to correctly define terminal states. Regenerate your protocol to identify if your protocol's dialogue rules are valid.

Please update to the latest packages by running `aea upgrade`.

## `v0.7.4` to `v0.7.5`

No backwards incompatible changes for skill and connection development.

## `v0.7.3` to `v0.7.4`

No backwards incompatible changes for skill and connection development.

## `v0.7.2` to `v0.7.3`

No backwards incompatible changes for skill and connection development.

## `v0.7.1` to `v0.7.2`

No backwards incompatible changes for skill and connection development.

## `v0.7.0` to `v0.7.1`

To improve performance, in particular optimize memory usage, we refactored the `Message` and `Dialogue` classes. This means all protocols need to be bumped to the latest version or regenerated using the `aea generate protocol` command in the <a href="../cli-commands/">CLI</a>.

## `v0.6.3` to `v0.7.0`

Multiple breaking changes require action in this order:

- Custom configuration overrides in `aea-config.yaml` are now identified via `public_id` rather than `author`, `name` and `version` individually. Please replace the three fields with the equivalent `public_id`.

- Run `aea upgrade` command to upgrade your project's dependencies. Note, you still do have to manually update the public ids under `default_routing` and `default_connection` in `aea-config.yaml` as well as the public ids in the non-vendor packages.

- Previously, connection `fetchai/stub`, skill `fetchai/error` and protocols `fetchai/default`, `fetchai/signing` and `fetchai/state_update` where part of the AEA distribution. Now they need to be fetched from registry. If you create a new project with `aea create` then this happens automatically. For existing projects, add the dependencies explicitly if not already present. You also must update the import paths as follows:

    - `aea.connections.stub` > `packages.fetchai.connections.stub`
    - `aea.protocols.default` > `packages.fetchai.protocols.default`
    - `aea.protocols.signing` > `packages.fetchai.protocols.signing`
    - `aea.protocols.state_update` > `packages.fetchai.protocols.state_update`
    - `aea.skills.error` > `packages.fetchai.skills.error`

- If you use custom protocols, regenerate them.

- In your own skills' `__init__.py` files add the public id (updating the string as appropriate):

``` python
from aea.configurations.base import PublicId


PUBLIC_ID = PublicId.from_str("author/name:0.1.0")
```
- The `fetchai/http` protocol's `bodyy` field has been renamed to `body`.

- Skills can now specify `connections` as dependencies in the configuration YAML.


## `v0.6.2` to `v0.6.3`

A new `upgrade` command is introduced to upgrade agent projects and components to their latest versions on the registry. To use the command first upgrade the AEA PyPI package to the latest version, then enter your project and run `aea upgrade`. The project's vendor dependencies will be updated where possible.

## `v0.6.1` to `v0.6.2`

No public APIs have been changed.

## `v0.6.0` to `v0.6.1`

The `soef` connection and `oef_search` protocol have backward incompatible changes.

## `v0.5.4` to `v0.6.0`

### `Dialogue` and `Dialogues` API updates

The dialogue and dialogues APIs have changed significantly. The constructor is different for both classes and there are now four primary methods for the developer:

- `Dialogues.create`: this method is used to create a new dialogue and message:
``` python
cfp_msg, fipa_dialogue = fipa_dialogues.create(
    counterparty=opponent_address,
    performative=FipaMessage.Performative.CFP,
    query=query,
)
```
The method will raise if the provided arguments are inconsistent.

- `Dialogues.create_with_message`: this method is used to create a new dialogue from a message:
``` python
fipa_dialogue = fipa_dialogues.create_with_message(
    counterparty=opponent_address,
    initial_message=cfp_msg
)
```
The method will raise if the provided arguments are inconsistent.

- `Dialogues.update`: this method is used to handle messages passed by the framework:
``` python
fipa_dialogue = fipa_dialogues.update(
    message=cfp_msg
)
```
The method will return a valid dialogue if it is a valid message, otherwise it will return `None`.

- `Dialogue.reply`: this method is used to reply within a dialogue:
``` python
proposal_msg = fipa_dialogue.reply(
    performative=FipaMessage.Performative.PROPOSE,
    target_message=cfp_msg,
    proposal=proposal,
)
```
The method will raise if the provided arguments are inconsistent.

The new methods significantly reduce the lines of code needed to maintain a dialogue. They also make it easier for the developer to construct valid dialogues and messages.

### `FetchAICrypto` - default crypto

The `FetchAICrypto` has been upgraded to the default crypto. Update your `default_ledger` to `fetchai`.

### Private key file naming

The private key files are now consistently named with the `ledger_id` followed by `_private_key.txt` (e.g. `fetchai_private_key.txt`). Rename your existing files to match this pattern.

### Type in package YAML

The package YAML files now contain a type field. This must be added for the loading mechanism to work properly.

### Moved address type

The address type has moved to `aea.common`. The import paths must be updated.

## `v0.5.3` to `v0.5.4`

The contract base class was slightly modified. If you have implemented your own contract package you need to update it accordingly.

The dialogue reference nonce is now randomly generated. This can result in previously working but buggy implementations (which relied on the order of dialogue reference nonces) to now fail.

## `v0.5.2` to `v0.5.3`

Connection states and logger usage in connections where updated. If you have implemented your own connection package you need to update it accordingly.

Additional dialogue consistency checks where enabled. This can result in previously working but buggy implementations to now fail.

## `v0.5.1` to `0.5.2`

No public APIs have been changed.

## `v0.5.0` to `0.5.1`

No public APIs have been changed.

## `v0.4.1` to `0.5.0`

A number of breaking changes where introduced which make backwards compatibility of skills rare.

- Ledger APIs <a href="../api/crypto/ledger_apis#ledger-apis-objects">`LedgerApis`</a> have been removed from the AEA constructor and skill context. `LedgerApis` are now exposed in the `LedgerConnection` (`fetchai/ledger`). To communicate with the `LedgerApis` use the `fetchai/ledger_api` protocol. This allows for more flexibility (anyone can add another `LedgerAPI` to the registry and execute it with the connection) and removes dependencies from the core framework.
- Skills can now depend on other skills. As a result, skills have a new required configuration field in `skill.yaml` files, by default empty: `skills: []`.

## `v0.4.0` to `v0.4.1`

There are no upgrade requirements if you use the CLI based approach to AEA development.

Connections are now added via <a href="../api/registries/resources#resources-objects">`Resources`</a> to the AEA, not the AEA constructor directly. For programmatic usage remove the list of connections from the AEA constructor and instead add the connections to resources.

## `v0.3.3` to `v0.4.0`

<ul>
<li> Message sending in the skills has been updated. In the past you had to construct messages, then serialize them and place them in an envelope:

``` python
cfp_msg = FipaMessage(...)
self.context.outbox.put_message(
    to=opponent_addr,
    sender=self.context.agent_address,
    protocol_id=FipaMessage.protocol_id,
    message=FipaSerializer().encode(cfp_msg),
)
# or
cfp_msg = FipaMessage(...)
envelope = Envelope(
    to=opponent_addr,
    sender=self.context.agent_address,
    protocol_id=FipaMessage.protocol_id,
    message=FipaSerializer().encode(cfp_msg),
)
self.context.outbox.put(envelope)
```

Now this has been simplified to:
``` python
cfp_msg = FipaMessage(...)
cfp_msg.counterparty = opponent_addr
self.context.outbox.put_message(message=cfp_msg)
```

You must update your skills as the old implementation is no longer supported.
</li>
<li> Connection constructors have been simplified. In the past you had to implement both the `__init__` as well as the `from_config` methods of a Connection. Now you only have to implement the `__init__` method which by default at load time now receives the following keyword arguments: `configuration: ConnectionConfig, identity: Identity, crypto_store: CryptoStore`. See for example in the scaffold connection:

``` python
class MyScaffoldConnection(Connection):
    """Proxy to the functionality of the SDK or API."""

    connection_id = PublicId.from_str("fetchai/scaffold:0.1.0")

    def __init__(
        self,
        configuration: ConnectionConfig,
        identity: Identity,
        crypto_store: CryptoStore,
    ):
        """
        Initialize a connection to an SDK or API.

        :param configuration: the connection configuration.
        :param crypto_store: object to access the connection crypto objects.
        :param identity: the identity object.
        """
        super().__init__(
            configuration=configuration, crypto_store=crypto_store, identity=identity
        )
```

As a result of this feature, you are now able to pass key-pairs to your connections via the `CryptoStore`.

You must update your connections as the old implementation is no longer supported.
</li>
</ul>


