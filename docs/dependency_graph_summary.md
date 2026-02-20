# Valory-xyz Repository Dependency Graph — Summary

This document describes every dependency edge in [`valory_dependency_graph.mmd`](./valory_dependency_graph.mmd).
For each edge you will find what the relationship means and a direct link to the file (or closest scope)
where the dependency is declared.

---

## Legend

| Symbol | Meaning |
|--------|---------|
| `A → B` | Repository A depends on / uses repository B |
| **pyproject.toml** | Python/Poetry runtime dependency |
| **packages/packages.json** | Open-AEA custom package registry (`third_party` = imported from B's `dev`) |
| **.gitmodules** | Git submodule — B is vendored inside A |
| **package.json** | npm/yarn dependency |
| **Cargo.toml** | Rust/Anchor dependency |
| **README** | Explicitly stated conceptual / functional dependency |

---

## 1. Foundation

### `open-autonomy` → `open-aea`
open-autonomy extends the open-aea framework with multi-agent service consensus (ABCI FSM),
agent service deployment tooling, and governance scaffolding.
Every open-autonomy agent service runs on top of an open-aea agent.

**Declaration:** [`pyproject.toml#L13`](https://github.com/valory-xyz/open-autonomy/blob/main/pyproject.toml#L13)
— `open-aea = { version = "==2.0.8", extras = ["all"] }`

---

### `open-aea` → `open-acn`
open-aea ships three ACN connection packages (`p2p_libp2p`, `p2p_libp2p_client`,
`p2p_libp2p_mailbox`) that allow AEA agents to communicate peer-to-peer over the
open-acn network.

**Declaration:** [`packages/packages.json#L19-L21`](https://github.com/valory-xyz/open-aea/blob/main/packages/packages.json#L19-L21)
— entries `connection/valory/p2p_libp2p/0.1.0`, `connection/valory/p2p_libp2p_client/0.1.0`,
`connection/valory/p2p_libp2p_mailbox/0.1.0`

---

### `dev-template` → `open-autonomy`
dev-template is a starter project template for building new open-autonomy agent services.
Its `packages/` directory contains a ready-to-use open-autonomy agent/service scaffold.

**Declaration:** [`README.md#L3`](https://github.com/valory-xyz/dev-template/blob/main/README.md#L3)
— "A template for development with the open-autonomy framework"

---

## 2. On-chain Protocol

### `autonolas-v1` → `autonolas-governance`
autonolas-v1 is the meta/integration-test repository for the entire Autonolas on-chain protocol.
It pulls autonolas-governance (OLAS token, veOLAS, governance Timelock) as a Git submodule
to run cross-repo integration tests.

**Declaration:** [`.gitmodules#L1`](https://github.com/valory-xyz/autonolas-v1/blob/main/.gitmodules#L1)
— `[submodule "lib/autonolas-governance"]`

---

### `autonolas-v1` → `autonolas-registries`
autonolas-v1 pulls autonolas-registries (ComponentRegistry, AgentRegistry, ServiceRegistry)
as a Git submodule for integration testing alongside the governance and tokenomics contracts.

**Declaration:** [`.gitmodules#L4`](https://github.com/valory-xyz/autonolas-v1/blob/main/.gitmodules#L4)
— `[submodule "lib/autonolas-registries"]`

---

### `autonolas-v1` → `autonolas-tokenomics`
autonolas-v1 pulls autonolas-tokenomics (Treasury, Tokenomics) as a Git submodule
for full-protocol integration tests.

**Declaration:** [`.gitmodules#L7`](https://github.com/valory-xyz/autonolas-v1/blob/main/.gitmodules#L7)
— `[submodule "lib/autonolas-tokenomics"]`

---

### `autonolas-v1` → `autonolas-marketplace`
autonolas-v1 pulls autonolas-marketplace as a Git submodule alongside the other
protocol contracts for integration testing.

**Declaration:** [`.gitmodules#L13`](https://github.com/valory-xyz/autonolas-v1/blob/main/.gitmodules#L13)
— `[submodule "lib/autonolas-marketplace"]`

---

### `autonolas-v1` → `autonolas-staking-programmes`
autonolas-v1 pulls autonolas-staking-programmes as a Git submodule for end-to-end
staking integration tests with the rest of the protocol.

**Declaration:** [`.gitmodules#L16`](https://github.com/valory-xyz/autonolas-v1/blob/main/.gitmodules#L16)
— `[submodule "lib/autonolas-staking-programmes"]`

---

### `autonolas-registries` → `autonolas-governance`
The registries contracts (ComponentRegistry, AgentRegistry, ServiceRegistry, ServiceManager)
are initialized with the governance contract address as their owner/manager.
Governance controls all privileged registry operations (upgrades, parameter changes).

**Declaration:** [`contracts/GenericManager.sol#L14`](https://github.com/valory-xyz/autonolas-registries/blob/main/contracts/GenericManager.sol#L14)
— `address public owner` — set to the governance Timelock address at deployment

---

### `autonolas-tokenomics` → `autonolas-governance`
Tokenomics contracts (Treasury, Tokenomics) require the governance address to control the
OLAS token minting schedule and policy parameters.

**Declaration:** [`contracts/Tokenomics.sol#L16`](https://github.com/valory-xyz/autonolas-tokenomics/blob/main/contracts/Tokenomics.sol#L16)
— inline `interface IOLAS` — declares the OLAS token (governance) interface used by Tokenomics

---

### `autonolas-tokenomics` → `autonolas-registries`
The Tokenomics contract reads from the ServiceRegistry to calculate per-component OLAS
incentives (unit fractions), reward epochs, and service donation splits.

**Declaration:** [`contracts/Tokenomics.sol#L43`](https://github.com/valory-xyz/autonolas-tokenomics/blob/main/contracts/Tokenomics.sol#L43)
— inline `interface IServiceRegistry` — declares the ServiceRegistry (registries) interface used by Tokenomics

---

### `autonolas-staking-programmes` → `autonolas-registries`
Staking programme contracts (StakingToken, StakingFactory) reference the ServiceRegistry
to verify service state (registered/deployed/terminated) as a condition for staking
eligibility.

**Declaration:** [`.gitmodules#L1`](https://github.com/valory-xyz/autonolas-staking-programmes/blob/main/.gitmodules#L1)
— `[submodule "lib/autonolas-registries"]` pinned at tag `v1.2.2`

---

### `autonolas-staking-programmes` → `autonolas-tokenomics`
Staking contracts call the Tokenomics/Treasury contracts to request OLAS staking rewards
for eligible stakers.

**Declaration:** [`contracts/contribute/Contributors.sol#L69`](https://github.com/valory-xyz/autonolas-staking-programmes/blob/main/contracts/contribute/Contributors.sol#L69)
— `address public immutable olas` — staking contracts hold and distribute OLAS (minted by Tokenomics) as staking rewards

---

### `autonolas-marketplace` → `autonolas-registries`
The Marketplace contracts look up service records from the ServiceRegistry to list, verify,
and facilitate trading of AI agent services.

**Declaration:** [`.gitmodules#L1`](https://github.com/valory-xyz/autonolas-marketplace/blob/main/.gitmodules#L1)
— `[submodule "lib/autonolas-registries"]`

---

### `dynamic-contribution` → `autonolas-registries`
The DynamicContribution contracts interact with the ServiceRegistry to retrieve
service/component metadata used for computing dynamic NFT contribution scores.

**Declaration:** [`contracts/DelegateContribute.sol#L4`](https://github.com/valory-xyz/dynamic-contribution/blob/main/contracts/DelegateContribute.sol#L4)
— `interface IVEOLAS` — interacts with the veOLAS governance contract from autonolas-registries/governance ecosystem

---

### `registries-solana` → `autonolas-registries`
registries-solana is a functional port of the EVM ServiceRegistry for the Solana/Anchor
runtime.  It mirrors the same on-chain registration API and data model as the EVM original.

**Declaration:** [`README.md#L1`](https://github.com/valory-xyz/registries-solana/blob/main/README.md#L1)
— "Set of Autonolas registries contracts on Solana"

---

### `governance-near` → `autonolas-governance`
governance-near is a functional port of the EVM governance contracts for the NEAR Protocol
runtime, mirroring the same governance interfaces in Rust/NEAR.

**Declaration:** [`README.md#L1`](https://github.com/valory-xyz/governance-near/blob/main/README.md#L1)
— "Set of Autonolas registries contracts on NEAR"

---

### `autonolas-subgraph` → `autonolas-registries`
The subgraph indexes on-chain events emitted by the Registries contracts
(ComponentRegistry, AgentRegistry, ServiceRegistry) to expose a queryable GraphQL API.

**Declaration:** [`.gitmodules#L1`](https://github.com/valory-xyz/autonolas-subgraph/blob/main/.gitmodules#L1)
— `[submodule "autonolas-registries"]` — provides ABIs and contract addresses

---

### `autonolas-subgraph` → `autonolas-tokenomics`
The subgraph also indexes Tokenomics and Treasury contract events (incentive epoch
checkpoints, OLAS minting) alongside the registry data.

**Declaration:** [`subgraphs/autonolas/subgraph.yaml#L1`](https://github.com/valory-xyz/autonolas-subgraph/blob/main/subgraphs/autonolas/subgraph.yaml#L1)
— tokenomics contract events are indexed alongside registries in the subgraph

---

### `autonolas-subgraph-studio` → `autonolas-subgraph`
The subgraph-studio monorepo supersedes and extends the original autonolas-subgraph,
housing multiple subgraphs (service-registry, tokenomics, staking) while reusing the
same ABI/schema patterns and referencing the same on-chain contracts.

**Declaration:** [`README.md#L1`](https://github.com/valory-xyz/autonolas-subgraph-studio/blob/main/README.md#L1)
— "This repository contains multiple subgraphs … primarily indexing contracts related to
the Autonolas ecosystem"

---

## 3. Operations & Middleware

### `olas-operate-middleware` → `open-autonomy`
The middleware is the Python backend of Pearl (and quickstart).  It uses the open-autonomy
Python SDK to deploy, run, and stop agent services locally, manage service keys, and
interact with the Autonolas protocol on-chain.

**Declaration:** [`pyproject.toml#L22`](https://github.com/valory-xyz/olas-operate-middleware/blob/main/pyproject.toml#L22)
— `open-autonomy = "^0.21.11"`

---

### `propel-client` → `open-autonomy`
propel-client is a CLI/SDK for interacting with the Valory PaaS (Propel).  It uses the
open-autonomy Python SDK to understand agent service concepts, service keys, and addresses.

**Declaration:** [`pyproject.toml#L14`](https://github.com/valory-xyz/propel-client/blob/main/pyproject.toml#L14)
— `open-autonomy = "==v0.19.7"`

---

## 4. Mech Ecosystem

### `mech` → `open-autonomy`
mech is a multi-agent service built on open-autonomy.  Its skills, protocols, and
connections are AEA packages that depend on the open-autonomy consensus framework.

**Declaration:** [`packages/packages.json#L42`](https://github.com/valory-xyz/mech/blob/main/packages/packages.json#L42)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `mech-predict` → `open-autonomy`
mech-predict extends mech with prediction-specific tools and inherits the full
open-autonomy ABCI FSM framework via its third_party AEA packages.

**Declaration:** [`packages/packages.json#L55`](https://github.com/valory-xyz/mech-predict/blob/main/packages/packages.json#L55)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `mech-agents-fun` → `open-autonomy`
mech-agents-fun provides agents.fun-specific mech tools.
Its AEA service packages are built on the open-autonomy framework.

**Declaration:** [`packages/packages.json#L48`](https://github.com/valory-xyz/mech-agents-fun/blob/main/packages/packages.json#L48)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `mock-mech` → `open-autonomy`
mock-mech is a lightweight mech simulator used in integration testing.
It depends on open-autonomy for its service scaffolding.

**Declaration:** [`README.md#L1`](https://github.com/valory-xyz/mock-mech/blob/main/README.md#L1)
— "A mock mech to test Olas services"

---

### `mech-marketplace-legacy` → `open-autonomy`
mech-marketplace-legacy is the v0 mech marketplace service.
It is a full open-autonomy agent service (all packages are internally owned).

**Declaration:** [`pyproject.toml#L19`](https://github.com/valory-xyz/mech-marketplace-legacy/blob/main/pyproject.toml#L19)
— `open-autonomy = "==0.18.2"`

---

### `mech-client` → `olas-operate-middleware`
mech-client is a Python CLI/SDK for requesting tasks from deployed mech services.
It uses olas-operate-middleware for on-chain service interaction, Safe management,
and OLAS staking.

**Declaration:** [`pyproject.toml#L17`](https://github.com/valory-xyz/mech-client/blob/main/pyproject.toml#L17)
— `olas-operate-middleware = "0.14.16"`

---

### `mech-tools-dev` → `open-autonomy`
mech-tools-dev is the developer toolkit for authoring and testing mech tools.
It imports the full open-autonomy framework for developing and running mech services.

**Declaration:** [`pyproject.toml#L19`](https://github.com/valory-xyz/mech-tools-dev/blob/main/pyproject.toml#L19)
— `open-autonomy = "==0.21.11"`

---

### `mech-tools-dev` → `mech-client`
mech-tools-dev uses mech-client to invoke deployed mech services during tool development
and integration testing.

**Declaration:** [`pyproject.toml#L54`](https://github.com/valory-xyz/mech-tools-dev/blob/main/pyproject.toml#L54)
— `mech-client = "==0.18.8"`

---

### `mech-tools-dev` → `olas-operate-middleware`
mech-tools-dev uses olas-operate-middleware for on-chain operations (Safe management,
staking) during mech tool integration tests.

**Declaration:** [`pyproject.toml#L55`](https://github.com/valory-xyz/mech-tools-dev/blob/main/pyproject.toml#L55)
— `olas-operate-middleware = ">=0.14.16"`

---

### `mech-predict` → `mech`
mech-predict imports mech's core AEA packages (agent_mech protocol, mech_abci skill,
acn_data_share protocol) in its `third_party` to reuse mech's prediction-task dispatching
logic.

**Declaration:** [`packages/packages.json#L34-L60`](https://github.com/valory-xyz/mech-predict/blob/main/packages/packages.json#L34-L60)
— `third_party` entries `protocol/valory/acn_data_share/0.1.0` (L34), `contract/valory/agent_mech/0.1.0` (L40),
and `skill/valory/mech_abci/0.1.0` (L60) — all owned by `mech`

---

### `mech-agents-fun` → `mech`
mech-agents-fun imports mech's core AEA packages in its `third_party` to reuse the mech
agent framework for agents.fun-specific tasks.

**Declaration:** [`packages/packages.json#L12-L23`](https://github.com/valory-xyz/mech-agents-fun/blob/main/packages/packages.json#L12-L23)
— `third_party` entries `protocol/valory/acn_data_share/0.1.0` (L12) and
`contract/valory/agent_mech/0.1.0` (L23) — owned by `mech`

---

### `mech-tools-dev` → `mech`
mech-tools-dev imports mech AEA packages (agent_mech, mech_abci, etc.) in its `third_party`
during local development and testing of new mech tools.

**Declaration:** [`packages/packages.json#L8-L36`](https://github.com/valory-xyz/mech-tools-dev/blob/main/packages/packages.json#L8-L36)
— `third_party` entries `protocol/valory/acn_data_share/0.1.0` (L8), `contract/valory/agent_mech/0.1.0` (L18),
and `skill/valory/mech_abci/0.1.0` (L36) — all owned by `mech`

---

### `mech-interact` → `open-autonomy`
mech-interact provides the `mech_interact_abci` skill for integrating mech request/response
cycles into any open-autonomy agent service.
It depends on the open-autonomy ABCI FSM framework.

**Declaration:** [`packages/packages.json#L41`](https://github.com/valory-xyz/mech-interact/blob/main/packages/packages.json#L41)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `mech-interact` → `mech`
mech-interact uses mech's core AEA packages (`protocol/valory/acn_data_share`,
`contract/valory/agent_mech`) to communicate with deployed mech agents on-chain and
off-chain.

**Declaration:** [`packages/packages.json#L22`](https://github.com/valory-xyz/mech-interact/blob/main/packages/packages.json#L22)
— `third_party` entry `protocol/valory/acn_data_share/0.1.0` (owned by `mech`)

---

## 5. AI Agent Services

### `trader` → `open-autonomy`
trader is an open-autonomy multi-agent service that autonomously trades prediction market
positions.  All its skills, connections, and protocols are AEA packages depending on
the open-autonomy framework.

**Declaration:** [`packages/packages.json#L71`](https://github.com/valory-xyz/trader/blob/main/packages/packages.json#L71)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `market-creator` → `open-autonomy`
market-creator is an open-autonomy agent service that autonomously creates Omen prediction
market questions using LLMs. Built on the open-autonomy ABCI FSM.

**Declaration:** [`packages/packages.json#L52`](https://github.com/valory-xyz/market-creator/blob/main/packages/packages.json#L52)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `optimus` → `open-autonomy`
optimus (BabyDegen) is an open-autonomy DeFi agent service for autonomous yield
optimization across DEXes and lending protocols.

**Declaration:** [`packages/packages.json#L62`](https://github.com/valory-xyz/optimus/blob/main/packages/packages.json#L62)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `meme-ooorr` → `open-autonomy`
meme-ooorr is an open-autonomy agent service for autonomous meme coin deployment,
management, and social promotion.

**Declaration:** [`packages/packages.json#L62`](https://github.com/valory-xyz/meme-ooorr/blob/main/packages/packages.json#L62)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `IEKit` → `open-autonomy`
IEKit is an open-autonomy agent service for evaluating the social impact of web3 projects
using on-chain and off-chain signals.

**Declaration:** [`packages/packages.json#L72`](https://github.com/valory-xyz/IEKit/blob/main/packages/packages.json#L72)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `price-oracle` → `open-autonomy`
price-oracle is the canonical open-autonomy demonstration service: multiple agents reach
BFT consensus on an off-chain price feed.

**Declaration:** [`packages/packages.json#L30`](https://github.com/valory-xyz/price-oracle/blob/main/packages/packages.json#L30)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `hello-world` → `open-autonomy`
hello-world is the simplest canonical open-autonomy example: a single-round FSM service
with a shared counter, used in tutorials.

**Declaration:** [`packages/packages.json#L23`](https://github.com/valory-xyz/hello-world/blob/main/packages/packages.json#L23)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `langchain-trader` → `open-autonomy`
langchain-trader is an open-autonomy agent service that uses LangChain LLMs to make
prediction market trading decisions.

**Declaration:** [`packages/packages.json#L32`](https://github.com/valory-xyz/langchain-trader/blob/master/packages/packages.json#L32)
— `third_party` entry `skill/valory/abstract_round_abci/0.1.0` (open-autonomy ABCI FSM skill)

---

### `pettai-agent` → `open-autonomy`
pettai-agent wraps an olas-sdk-starter-based agent service.  The `olas-sdk-starter/`
subdirectory contains an open-autonomy agent/service scaffold registered on the Autonolas
protocol.

**Declaration:** [`olas-sdk-starter/packages/packages.json#L3`](https://github.com/valory-xyz/pettai-agent/blob/main/olas-sdk-starter/packages/packages.json#L3)
— `dev` section agent/service packages built on open-autonomy

---

### `agents-fun-eliza` → `open-autonomy`
agents-fun-eliza is an open-autonomy agent service that integrates the ElizaOS framework
for autonomous social media actions (Twitter/X).

**Declaration:** [`packages/packages.json#L3`](https://github.com/valory-xyz/agents-fun-eliza/blob/main/packages/packages.json#L3)
— `third_party` open-autonomy packages

---

### `eliza-memeooorr-olas-sdk` → `olas-sdk-starter`
eliza-memeooorr-olas-sdk was scaffolded from the olas-sdk-starter template.
Its `packages/packages.json` is empty (no AEA third_party deps), meaning all AEA
components are authored locally following the sdk-starter pattern.

**Declaration:** [`packages/packages.json`](https://github.com/valory-xyz/eliza-memeooorr-olas-sdk/blob/main/packages/packages.json)
— `{"dev": {}, "third_party": {}}`; also [`README.md`](https://github.com/valory-xyz/eliza-memeooorr-olas-sdk/blob/main/README.md)
— content matches the olas-sdk-starter template

---

### `agents-fun-eliza` → `plugin-memeooorr`
agents-fun-eliza is the open-autonomy backend agent that uses `plugin-memeooorr` as its
TypeScript/ElizaOS plugin for Twitter interactions and meme-coin decision actions.

**Declaration:** [`README.md#L1`](https://github.com/valory-xyz/plugin-memeooorr/blob/main/README.md#L1)
— "specifically designed to be used with agents-fun-eliza"

---

### `trader` → `mech`
trader uses mech's `protocol/valory/acn_data_share` AEA protocol (for mech request
routing) and `contract/valory/agent_mech` (for on-chain mech contract interactions)
in its AEA package set.

**Declaration:** [`packages/packages.json#L31`](https://github.com/valory-xyz/trader/blob/main/packages/packages.json#L31)
— `third_party` entry `protocol/valory/acn_data_share/0.1.0` (owned by `mech`)

---

### `market-creator` → `mech`
market-creator imports mech's `protocol/valory/acn_data_share` to enable mech task
delegation for LLM-powered market question creation.

**Declaration:** [`packages/packages.json#L20`](https://github.com/valory-xyz/market-creator/blob/main/packages/packages.json#L20)
— `third_party` entry `protocol/valory/acn_data_share/0.1.0` (owned by `mech`)

---

### `meme-ooorr` → `mech`
meme-ooorr imports mech AEA packages to use mech agents for AI-assisted meme coin
strategy analysis.

**Declaration:** [`packages/packages.json#L24`](https://github.com/valory-xyz/meme-ooorr/blob/main/packages/packages.json#L24)
— `third_party` entry `protocol/valory/acn_data_share/0.1.0` (owned by `mech`)

---

### `IEKit` → `mech`
IEKit imports mech AEA packages to delegate AI reasoning tasks to mech agents as part
of its impact evaluation pipeline.

**Declaration:** [`packages/packages.json#L42`](https://github.com/valory-xyz/IEKit/blob/main/packages/packages.json#L42)
— `third_party` entry `protocol/valory/acn_data_share/0.1.0` (owned by `mech`)

---

### `trader` → `mech-interact`
trader's prediction market FSM uses the `skill/valory/mech_interact_abci` skill from
mech-interact to send/receive mech requests during trading rounds.

**Declaration:** [`packages/packages.json#L76`](https://github.com/valory-xyz/trader/blob/main/packages/packages.json#L76)
— `third_party` entry `skill/valory/mech_interact_abci/0.1.0` (owned by `mech-interact`)

---

### `market-creator` → `mech-interact`
market-creator uses `skill/valory/mech_interact_abci` to delegate market question
creation tasks to mech agents.

**Declaration:** [`packages/packages.json#L57`](https://github.com/valory-xyz/market-creator/blob/main/packages/packages.json#L57)
— `third_party` entry `skill/valory/mech_interact_abci/0.1.0` (owned by `mech-interact`)

---

### `meme-ooorr` → `mech-interact`
meme-ooorr uses `skill/valory/mech_interact_abci` to integrate mech-based AI reasoning
into its meme-coin strategy rounds.

**Declaration:** [`packages/packages.json#L65`](https://github.com/valory-xyz/meme-ooorr/blob/main/packages/packages.json#L65)
— `third_party` entry `skill/valory/mech_interact_abci/0.1.0` (owned by `mech-interact`)

---

### `IEKit` → `mech-interact`
IEKit uses `skill/valory/mech_interact_abci` to request mech evaluations as part of its
impact scoring pipeline.

**Declaration:** [`packages/packages.json#L75`](https://github.com/valory-xyz/IEKit/blob/main/packages/packages.json#L75)
— `third_party` entry `skill/valory/mech_interact_abci/0.1.0` (owned by `mech-interact`)

---

### `langchain-trader` → `mech-interact`
langchain-trader uses `skill/valory/mech_interact_abci` to dispatch LLM-powered
prediction tasks to mech agents.

**Declaration:** [`packages/packages.json#L35`](https://github.com/valory-xyz/langchain-trader/blob/master/packages/packages.json#L35)
— `third_party` entry `skill/valory/mech_interact_abci/0.1.0` (owned by `mech-interact`)

---

## 6. End-User Applications

### `olas-operate-app (Pearl)` → `olas-operate-middleware`
Pearl is an Electron desktop app for one-click deployment and management of agent
services.  Its Python backend daemon is olas-operate-middleware, installed as a
Poetry dependency.

**Declaration:** [`pyproject.toml#L13`](https://github.com/valory-xyz/olas-operate-app/blob/main/pyproject.toml#L13)
— `olas-operate-middleware = "0.14.15"`

---

### `quickstart` → `olas-operate-middleware`
quickstart is a CLI script for one-click deployment of specific agent services.
It calls the olas-operate-middleware Python API to manage service lifecycles.

**Declaration:** [`pyproject.toml#L13`](https://github.com/valory-xyz/quickstart/blob/main/pyproject.toml#L13)
— `olas-operate-middleware = "0.14.4"`

---

### `olas-sdk-starter` → `open-autonomy`
olas-sdk-starter is the official project template for building custom open-autonomy agent
services that can be deployed via Pearl or quickstart.  Its scaffold uses the
`autonomy` CLI extensively.

**Declaration:** [`README.md#L3`](https://github.com/valory-xyz/olas-sdk-starter/blob/main/README.md#L3)
— uses `autonomy init`, `autonomy packages lock`, `autonomy push-all`

---

### `open-autonomy-client` → `open-autonomy`
open-autonomy-client is a Python SDK for querying deployed open-autonomy multi-agent
services as if they were a single consensus endpoint, abstracting away the multi-agent
nature.

**Declaration:** [`README.md#L1`](https://github.com/valory-xyz/open-autonomy-client/blob/main/README.md#L1)
— "helps to query multi-agent systems built with the open-autonomy framework"

---

### `triton-bot` → `olas-operate-middleware`
triton-bot is a Telegram bot that queries the local Pearl/middleware node to display
agent service staking status and metrics to users.

**Declaration:** [`pyproject.toml#L12`](https://github.com/valory-xyz/triton-bot/blob/main/pyproject.toml#L12)
— `olas-operate-middleware = "^0.13.1"`

---

## 7. Frontends

### `autonolas-frontend-mono` → `olas-predict`
autonolas-frontend-mono is the Olas Network web app monorepo.  The Olas Predict UI
(`olas-predict`) is one of its hosted applications.

**Declaration:** [Repository structure](https://github.com/valory-xyz/autonolas-frontend-mono)
— olas-predict is included as one of the apps in the monorepo

---

### `olas-predict` → `trader`
olas-predict is the prediction market UI that displays market positions and performance
metrics produced by the trader agent service.  It is the primary end-user interface for
viewing trader output.

**Declaration:** [`pages/`](https://github.com/valory-xyz/olas-predict/tree/main/pages)
— UI pages render trader agent prediction markets, trades, and balances

---

### `olas-predict` → `autonolas-subgraph`
olas-predict fetches on-chain prediction market data (market registry, staking, token
supply) from the autonolas-subgraph via GraphQL.

**Declaration:** [`.env.example#L1-L3`](https://github.com/valory-xyz/olas-predict/blob/main/.env.example#L1-L3)
— `NEXT_PUBLIC_SUBGRAPH_API_KEY` (L1), `NEXT_PUBLIC_REGISTRY_GRAPH_URL` (L3);
[`package.json`](https://github.com/valory-xyz/olas-predict/blob/main/package.json)
— `graphql-request` dependency

---

## 8. Documentation

### `docs` → `open-aea`
The docs repo pulls open-aea documentation as a Git submodule, incorporating it into
the unified Olas ecosystem docs site built with MkDocs.

**Declaration:** [`.gitmodules#L1`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L1)
— `[submodule "open-aea"]`

---

### `docs` → `open-autonomy`
The docs repo pulls open-autonomy documentation as a Git submodule.

**Declaration:** [`.gitmodules#L4`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L4)
— `[submodule "open-autonomy"]`

---

### `docs` → `open-acn`
The docs repo pulls open-acn documentation as a Git submodule.

**Declaration:** [`.gitmodules#L7`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L7)
— `[submodule "open-acn"]`

---

### `docs` → `mech`
The docs repo pulls mech documentation as a Git submodule.

**Declaration:** [`.gitmodules#L10`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L10)
— `[submodule "mech"]`

---

### `docs` → `mech-tools-dev`
The docs repo pulls mech-tools-dev developer tool documentation as a Git submodule.

**Declaration:** [`.gitmodules#L13`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L13)
— `[submodule "mech-tools-dev"]`

---

### `docs` → `mech-client`
The docs repo pulls mech-client API reference documentation as a Git submodule.

**Declaration:** [`.gitmodules#L16`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L16)
— `[submodule "mech-client"]`

---

### `docs` → `price-oracle`
The docs repo pulls price-oracle tutorial/example documentation as a Git submodule.

**Declaration:** [`.gitmodules#L19`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L19)
— `[submodule "price-oracle"]`

---

### `docs` → `IEKit`
The docs repo pulls IEKit documentation as a Git submodule.

**Declaration:** [`.gitmodules#L22`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L22)
— `[submodule "IEKit"]`

---

### `docs` → `hello-world`
The docs repo pulls hello-world tutorial documentation as a Git submodule.

**Declaration:** [`.gitmodules#L25`](https://github.com/valory-xyz/docs/blob/main/.gitmodules#L25)
— `[submodule "hello-world"]`
