# CLAUDE

This file provides guidance to Claude Code (`claude.ai/code`) when working with code in this repository.

## Project Overview

Open AEA (Autonomous Economic Agent) Framework — a Python framework for building autonomous economic agents, forked from Fetch.AI's AEA to remove vendor lock-in. Maintained by Valory AG. Supports Python 3.10–3.14.

## Common Commands

### Environment Setup
```bash
make new_env          # Create poetry environment with all dev dependencies
poetry shell          # Enter virtual environment
```

### External Tools (optional, needed for full test suite)
```bash
# Protobuf compiler (needed for protocol generator tests)
# macOS: brew install protobuf
# Linux: download from https://github.com/protocolbuffers/protobuf/releases

# protolint (needs Go installed)
make protolint_install

# IPFS v0.6.0 (needed for TestDirectoryHashing only)
# Download from https://github.com/valory-xyz/open-aea/releases/tag/ipfs-v0.6.0-binaries
```

### Formatting and Linting
```bash
make formatters       # Run isort + black via tox
make code-checks      # Run all linters in parallel (black-check, isort-check, flake8, mypy, pylint, vulture, darglint)
make security         # Run bandit, safety, gitleaks
```

### Testing
```bash
# Run all tests with coverage
make test

# Test a specific submodule (aea.{SUBMODULE} with tests/test_{TESTMODULE})
make dir=cli tdir=cli test-sub

# Test a specific package
make dir=skills tdir=packages/test_skills test-sub-p

# Run a single test file directly
pytest tests/test_aea.py -rfE

# Run a single test
pytest tests/test_aea.py::TestAEA::test_name -rfE

# Full tox matrix
make test-all
```

### When Modifying Files in `packages/`
```bash
make generators       # Regenerate hashes, docs, copyright headers, protocol code
make common-checks-1  # Verify copyright, hashes, package dependencies
make common-checks-2  # Check API docs and doc link hashes
make hashes           # Just regenerate package hashes (via `tox -e lock-packages`)
```

### Protocol Buffers
```bash
make build-proto      # Compile .proto files (requires INCLUDE=PATH_TO_PROTOC_INCLUDE)
make protolint        # Lint .proto files
```

## Code Style

- **Black** with line length 88, **`isort`** with black-compatible profile
- **Docstrings**: Sphinx style (enforced by `darglint`)
- All files must include the Apache 2.0 license header (checked by `tox -e fix-copyright`)
- Generated `*_pb2.py` files are excluded from all linting

## Architecture

### Core Framework (`aea/`)

The AEA runtime is an `asyncio`-based agent loop. Key classes:

- **`AEA`** (`aea/aea.py`) — Main agent class inheriting from `Agent`. Manages life cycle, communications, and resource coordination
- **`AEABuilder`** (`aea/aea_builder.py`) — Programmatic agent construction, configuration loading, dependency resolution
- **`Multiplexer`** (`aea/multiplexer.py`) — Communication hub managing multiple connections, with `InBox`/`OutBox` message queues

### Component Model

Agents are composed of four component types, each loaded via configuration:

- **Skills** (`aea/skills/`) — Agent behaviour: **Handlers** (reactive, respond to messages), **Behaviours** (proactive, internally triggered), **Models** (state), **Tasks** (background work). Skills are horizontally arranged and can compete.
- **Protocols** (`aea/protocols/`) — Define message syntax and dialogues. Use Protocol Buffers for serialization. Each skill maps to at least one protocol.
- **Connections** (`aea/connections/`) — Network/service interfaces wrapping SDKs/APIs. Translate between Envelopes/Messages and external protocols.
- **Contracts** (`aea/contracts/`) — Blockchain smart contract wrappers.

Communication uses **Envelopes** (`to`, `sender`, `protocol_id`, `message`, `context`) routed through the `Multiplexer`.

### Plugin System (`plugins/`)

Ledger integrations and CLI extensions are plugins, each with their own `setup.py` and tests:
- `aea-ledger-ethereum`, `aea-ledger-cosmos`, `aea-ledger-fetchai`, `aea-ledger-solana`
- `aea-ledger-ethereum-flashbots`, `aea-ledger-ethereum-hwi`
- `aea-cli-ipfs`, `aea-cli-benchmark`

Crypto implementations are registered via a plugin registry (`aea/crypto/`).

### Packages (`packages/`)

Reusable agent components organized by vendor (`fetchai/`, `valory/`, `open_aea/`), each containing agents, connections, contracts, protocols, and skills. Package integrity is verified via hash checking (`make hashes`, `tox -e hash-check`).

### CLI (`aea/cli/`)

Click-based CLI (entry point: `aea`). Supports creating, running, and managing agents and packages.

### Tests (`tests/`)

Pytest with custom markers: `integration` (requires external services), `ledger` (requires test networks), `flaky`, `unstable` (excluded from CI), `sync`, `profiling`. Test config in `pytest.ini`. Large `conftest.py` with shared fixtures.

## Pre-PR Checklist

1. `make clean`
2. `make formatters`
3. `make code-checks`
4. `make security`
5. If `packages/` modified: `make generators` then `make common-checks-1` and `make common-checks-2`
6. If `packages/` not modified: `make check-copyright`

## Before every commit — always run these

Do NOT commit until every check below passes locally. Do not cherry-pick
a subset; each one has caught real regressions. When linters report no
findings you are much better off than inferring from the output of a
partial run.

The full set (per tox env):

```bash
tox -e black-check
tox -e isort-check
tox -e flake8
tox -e check-copyright
tox -e spell-check
tox -e darglint        # catches missing :param: / :return: lines
tox -e dependencies-check
tox -e hash-check      # only if packages/ or aea/ scaffolds touched
tox -e check-doc-links-hashes  # only if docs/ touched
```

Notes:
- `darglint` scans `plugins/**/build/` artifacts if they exist. If you
  see a darglint error in a `build/lib/...` path, run `rm -rf
  plugins/*/build` and re-run — those are stale setuptools build
  outputs, not real source.
- For Go changes under `libs/go/aealite` or
  `packages/valory/connections/p2p_libp2p/libp2p_node`, also run
  `go build ./... && go vet ./... && go test ./...` in each module,
  plus `golangci-lint run --timeout=5m` on aealite (libp2p_node is
  not covered by golangci-lint yet — see CLEANUP.md).
- `make code-checks` bundles most of the Python tox envs above but
  runs them in parallel; if it fails, re-run the failing ones
  individually to see which one reported what.
