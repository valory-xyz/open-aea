# Repo Cleanup Candidates

Audit of items that could be removed or simplified to reduce repo surface area.

## Definitely removable

### `scripts/check_pipfile_and_toxini.py`

References non-existent `Pipfile` (project migrated to Poetry/pyproject.toml). Replaced by `scripts/check_pyproject_and_toxini.py`. Not referenced in Makefile, tox.ini, or CI.

### `mints/`

Contains a single `whitelist.txt` listing component names to skip during minting. Not referenced in any code, CI workflow, Makefile, or script. Vestigial from an on-chain component-minting workflow that no longer runs from this repo.

### Stale tox.ini envlist entries

The following environments are declared in the `envlist` but have no corresponding `[testenv:xxx]` sections:

- `py3.10-cov`, `plugins-py3.10-cov`, `packages-py3.10-cov`
- `py3.15`, `plugins-py3.15`, `packages-py3.15`
- `plugins_deps`

## Likely removable

### `libs/go/`

Go implementation of aealite. The `golang_checks` CI job exists but has **no actual test steps** — it only sets up Go. Last meaningful commit was ~9 months ago. If Go support is not actively maintained, this is dead weight. Also has a code scanning alert (#13: `InsecureSkipVerify: true` in `connections/tcpsocket.go`) — dismissed as dead code but worth noting.

### `examples/aealite_go/`

Tiny Go example (53-byte README). Dead if `libs/go/` is removed.

### Unused scripts in `scripts/`

These scripts are not referenced in CI, Makefile, or tox.ini:

- `deploy_to_registry.py` — manual package deployment utility
- `log_parser.py` — test log parsing utility
- `parse_main_dependencies_from_lock.py` — lock file parsing utility
- `publish_packages_to_local_registry.py` — manual local registry deployment
- `spell-check.sh` — spell checking (never invoked)

## Partially removable (incomplete Poetry migration)

### `setup.py`

Still needed because `release.yml` uses `python setup.py sdist bdist_wheel` to build distributions. Could be removed if the release workflow were migrated to use `python -m build` (which reads `pyproject.toml`).

### `setup.cfg`

Contains tool configurations for flake8, isort, mypy, darglint, and bdist_wheel. These could be consolidated into `pyproject.toml` `[tool.xxx]` sections, allowing removal of this file.

### `scripts/install.sh` and `scripts/install.ps1`

End-user install scripts that install from PyPI. Referenced in `bump_aea_version.py` for version string updates. Hardcode version 2.1.0 — questionable ongoing maintenance value.

## Dependabot alerts requiring action

### Go: `packages/valory/connections/p2p_libp2p/libp2p_node/go.mod` (15 alerts)

Active package with outdated Go dependencies. Needs dependency bumps for:

- `github.com/ethereum/go-ethereum` — 5 alerts (high+medium): DoS via malicious p2p messages, ECIES public key validation
- `golang.org/x/crypto` — 4 alerts (critical+high+medium): SSH auth bypass, DoS, unbounded memory, Terrapin attack
- `github.com/btcsuite/btcd` — 2 alerts (high+medium): FindAndDelete bug, consensus failures
- `github.com/libp2p/go-libp2p-kad-dht` — 1 alert (medium): content censorship via DHT abuse
- `google.golang.org/protobuf` — 1 alert (medium): infinite loop in protojson.Unmarshal

### Python: `plugins/aea-ledger-cosmos/setup.py` (2 alerts)

`ecdsa` is a runtime dependency of the cosmos ledger plugin:

- #122 (high): Minerva timing attack on P-256
- #147 (medium): DoS via improper DER length validation

### Python: `requests` in core (1 alert)

- #159 (medium): Insecure temp file reuse in extract_zipped_paths(). Goes away when PR #867 (remove requests from core) merges.

## Confirmed keep

### `*-image/` directories (deploy, develop, docs, user)

All four are published to Docker Hub via `release.yml`. Actively maintained.

### `benchmark/`

Linted across all tox linter targets. Internal performance testing framework documented in `docs/performance-benchmark.md`.

### `plugins/aea-cli-benchmark/`

Published to PyPI on every release. Provides the user-facing `aea benchmark` CLI command.

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
| `cosmos` | `ecdsa>=0.15,<0.17`, `bech32`, `pycryptodome`, `cosmpy`, `requests` | 2 open Dependabot alerts on `ecdsa` (Minerva timing attack #122 high, DER DoS #147 medium) |
| `ethereum` | `web3>=7.0.0,<8`, `eth-account>=0.13.0,<0.14`, `requests` | web3 is heavy but canonical |
| `fetchai` | inherits `cosmos`, plus `requests` | same alerts propagate |
| `ethereum-hwi` | inherits `ethereum`, plus `ledgerwallet`, `construct`, `protobuf` | hardware wallet niche |
| `solana` | `cryptography`, `PyNaCl>=1.5.0,<2`, `solders`, `solana`, `anchorpy` | **`PyNaCl` is declared but never imported** (dead dep) |
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
| 1 | Remove unused `PyNaCl` from `plugins/aea-ledger-solana/setup.py` | trivial | dead dep removed | zero — grep confirms zero `import nacl`/`from nacl` in the plugin source | **Do immediately** |
| 2 | Replace `ecdsa` with `coincurve` in `plugins/aea-ledger-cosmos/aea_ledger_cosmos/cosmos.py` and `packages/valory/connections/p2p_libp2p_client/connection.py`, `packages/valory/connections/p2p_libp2p_mailbox/connection.py` | medium (~50 LOC per site + real-chain testing) | closes 2 Dependabot alerts (#122 Minerva high, #147 DER DoS medium), faster sign/verify (C vs pure Python), aligns with ethereum's transitive stack | medium — signature format compatibility must be preserved exactly (canonical DER for ACN, sigencode_string_canonize for cosmos) or nodes reject transactions | **Worth doing** — directly addresses open security alerts |
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
