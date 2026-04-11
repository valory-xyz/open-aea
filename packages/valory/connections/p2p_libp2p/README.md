# P2P Libp2p Connection

This connection enables point-to-point secure end-to-end encrypted communication between agents in a fully decentralized way.
The connection deploys a node that collectively maintains a distributed hash table (DHT) along with other nodes in the same network.
The DHT provides proper messages delivery by mapping agents addresses to their locations.

## Usage

First, add the connection to your AEA project: `aea add connection valory/p2p_libp2p:0.26.0`.

Next, ensure that the connection is properly configured by setting:

- `local_uri` to the local IP address and port number that the node should use, in format `${ip}:${port}`
- `public_uri` to the external IP address and port number allocated for the node, can be the same as `local_uri` if running locally
- `entry_peers` to a list of multiaddresses of already deployed nodes to join their network, should be empty for genesis node
- `delegate_uri` to the IP address and port number for the delegate service, leave empty to disable the service

If the delegate service is enabled, then other AEAs can connect to the peer node using the `valory/p2p_libp2p_client:0.20.0` connection.


## Example: setting up the ACN locally

Cosmos uses the secp256k1 key format that we require for the ACN's proof of representation.
We can easily generate keys on demand using the open-aea framework:

```bash
function setup {
    aea create $1 --local
    cd $1
    aea generate-key cosmos && \
    aea add-key cosmos && \
    echo "" && echo "created agent: $1"
    echo "    private key: $(cat cosmos_private_key.txt | tr -d \\n )" && \
    echo "    public key:  $(aea get-public-key cosmos)" && \
    echo "    PeerID:      $(aea get-multiaddress cosmos)" && \
    echo "" && cd ../ && rm -r $1
}

setup bootstrap_peer
setup entry_node_1
setup entry_node_2
```

The output looks as follows:
```bash
Initializing AEA project 'bootstrap_peer'
Creating project directory './bootstrap_peer'
Creating config file aea-config.yaml
Adding default packages ...
Adding protocol 'open_aea/signing:1.0.0:bafybeiambqptflge33eemdhis2whik67hjplfnqwieoa6wblzlaf7vuo44'...
Successfully added protocol 'open_aea/signing:1.0.0'.

created agent: bootstrap_peer
    private key: 401e39213ca22d324c3259b51585571948139cdd0ba0e3d34d93b61bbea292b5
    public key:  025d1076b5571ac239bd269bcd5a6a004d035c17ad8b3de899fa6144e8f57d3310
    PeerID:      16Uiu2HAm1gxTRqk1ao3WYTE7bNR78f3sqriWLtWpfNNVP1T66B2P

...
created agent: entry_node_1
    private key: db26b697be0e6fc02bbe147050e1eeb847bc98b7f2ffbd1f0eb06922786a3eb4
    public key:  035198c3e4517b3be0f3ae61387c2e92427c04bae33486cc9fa6e9b39a52e32c4f
    PeerID:      16Uiu2HAmJ9WUpYQKefzwgxJtceyTjFEidMHP8MHAcbfkrZKwuQSi

...
created agent: entry_node_2
    private key: 1d73b10bc8e4f6e1dd84e644a7d895e6132dfc15fe6e7234bf52f94b90ce9bb6
    public key:  0286bac6348f025fb2ae5a223adc2dc99844546cb4cb6a6dec84bba052ebbaddac
    PeerID:      16Uiu2HAm4Vbo6bv8G2jdYARsm8wNXogFAdL6c87P7uQGTWh7uey9
```

Instructions in the [open-acn README.md](https://github.com/valory-xyz/open-acn)
can than be followed to set up the network.

## Wire compatibility notice — libp2p v0.8 → v0.33 bump

The embedded `libp2p_node` Go binary was upgraded from `go-libp2p v0.8.x` to
`go-libp2p v0.33.2` to close 14 open Dependabot security alerts (one critical
`x/crypto` SSH auth bypass, six high-severity `go-ethereum` and `x/crypto`
DoS issues, plus medium alerts in `btcd`, `protobuf`, and `x/crypto`).

**Behavioural parity with the pre-bump binary is preserved**: every routing
topology that worked under `go-libp2p v0.8` (direct peer-to-peer, delegate
clients, same-relay DHT clients, AND clients reserved with different relays
in the same DHT) still works under v0.33. This required a number of explicit
opt-ins on the v0.33 side because libp2p split apart what `EnableRelay()`
implicitly did in v0.8 — see the migration notes below.

The bump preserves the direct peer-to-peer wire format but **breaks
circuit-relay wire compatibility** with nodes still running pre-bump
releases, because the libp2p project itself rewrote the circuit-relay
protocol between v0.8 and v0.21 and removed the v1 implementation upstream.

### What stays compatible

The transport stack underneath the relay layer is wire-stable across this
range of libp2p:

- **TCP** transport
- **noise** / **TLS** security handshake
- **yamux v1** stream multiplexer
- **multistream-select** protocol negotiation
- **Identify** protocol
- **Protobuf** envelope wire format (verified backward-compatible from
  protobuf runtime `1.28.x` through `1.36.x`)
- The AEA-level application protocols served by this connection
  (`/aea-register/0.1.0`, `/aea/0.1.0`, `/aea-address/0.1.0`) — message
  bodies and protocol IDs are unchanged

This means a new node and an old node can still talk to each other
**directly** when both endpoints are publicly reachable (or when both are
on the same LAN segment).

### What is BROKEN

The libp2p project rewrote the circuit-relay protocol between v0.8 and the
current release. v1 was deprecated around v0.18 and **removed entirely
around v0.21**. The two protocols use different protocol IDs and different
wire framings:

| libp2p version | Circuit relay protocol IDs |
|---|---|
| v0.8 (old `libp2p_node` releases ≤ v2.1.0) | `/libp2p/circuit/relay/0.1.0` |
| v0.33 (current `libp2p_node`) | `/libp2p/circuit/relay/0.2.0/hop`, `/libp2p/circuit/relay/0.2.0/stop` |

A v0.33 client cannot reserve a slot with — or dial via — a v0.8 relay,
and vice versa. The libp2p libraries no longer carry the v1 implementation
in their source tree, so dual-stacking would require either staying on a
transitional libp2p version (v0.18–v0.20.x, where both v1 and v2 were
available) or vendoring an out-of-tree v1 implementation indefinitely.

### Concrete consequences for mixed-version deployments

| Scenario | Works on this release? |
|---|---|
| New node ↔ new node, direct (no relay) | ✅ |
| New node ↔ new node, via relay | ✅ |
| Old node ↔ old node | ✅ (unaffected) |
| New node ↔ old node, both publicly reachable, direct | ✅ |
| New node behind NAT trying to use an OLD relay | ❌ — new client speaks circuit v2, old relay only speaks v1 |
| Old node behind NAT trying to use a NEW relay | ❌ — old client speaks circuit v1, new relay only speaks v2 |
| New node delegate-client (via `valory/p2p_libp2p_client`) talking to either era of peer | ✅ — delegate path does not use circuit relay |

In short: **anything that needs the circuit-relay path must be running the
same era on both sides**. Direct peer-to-peer envelope routing and the
delegate-client path are unaffected.

### Operational guidance

1. **Coordinated upgrade ("flag day")** — the simplest path. Schedule a
   short window where every node operating a publicly-reachable relay or
   relying on a relay is upgraded together. After the window, only the new
   binary is in service.
2. **Direct-only legacy bridges** — if some old nodes must remain online
   during a longer transition, configure them with publicly reachable
   `public_uri` so peers don't need to use relay-mediated dialing.
3. **Delegate-client fallback** — agents that previously connected via the
   relay can switch to `valory/p2p_libp2p_client` against a new-era node;
   that path uses TCP+TLS rather than libp2p circuit relay and is wire
   stable across the bump.

### Why we accepted the break

Staying on libp2p v0.8 would leave 15 Dependabot alerts open indefinitely,
including a critical `golang.org/x/crypto` SSH `ServerConfig.PublicKeyCallback`
authorization-bypass issue. Targeting an intermediate libp2p version
(v0.18–v0.20.x) that still ships circuit v1 would only partially close the
alert set — the older transitive dependency graph (`go-ethereum`, `x/crypto`,
`btcd`) carries its own unfixed issues — and would not eliminate the eventual
need for this break.

### libp2p v0.8 → v0.33 migration notes (relay path)

The pre-bump code only said `libp2p.EnableRelay()` on the client and
`libp2p.EnableRelay(circuit.OptHop)` on the relay node, and the entire
auto-relay lifecycle (reservation, address publication, transient-vs-direct
connection accounting) was implicit. In v0.33 those behaviours are split
across several explicit options. To preserve parity, the dhtpeer (relay
node) and dhtclient sides now do the following:

**`dht/dhtpeer/dhtpeer.go` — relay-side options:**

```go
libp2p.EnableRelayService(),
libp2p.ForceReachabilityPublic(),
```

`EnableRelayService` is the v2 replacement for the old
`EnableRelay(circuit.OptHop)` form. `ForceReachabilityPublic` is required
because v0.33's relay service only advertises the
`/libp2p/circuit/relay/0.2.0/hop` protocol once AutoNAT has confirmed
public reachability; without forcing it, clients trying to reserve a slot
get `protocols not supported [hop]`.

**`dht/dhtclient/dhtclient.go` — client-side options:**

```go
libp2p.EnableRelay(),
libp2p.ForceReachabilityPrivate(),
libp2p.EnableAutoRelayWithStaticRelays(dhtClient.bootstrapPeers),
```

`EnableRelay()` keeps the relay transport available. `ForceReachabilityPrivate`
is needed because the client uses `libp2p.ListenAddrs()` (no listen
addresses), which prevents AutoNAT from determining reachability; auto-relay
won't kick off a reservation until reachability is "private", so we force
it. `EnableAutoRelayWithStaticRelays(bootstrapPeers)` does the actual
reservation lifecycle and — importantly — adds the resulting
`/p2p-circuit` address to the host's address list, which propagates to
other peers via Identify (recovering the v0.8 auto-relay address-publication
behaviour).

**`dht/dhtclient/dhtclient.go::SetupDHTClient` — synchronous wait:**

After bootstrap, the setup blocks in `waitForCircuitAddress` until the
host's address list contains a `/p2p-circuit` component. Without this
wait the client could be observed by other peers before its reservation
completes, leading to dial failures.

**`dht/dhtclient/dhtclient.go::newStreamLoopUntilTimeout` — transient opt-in:**

```go
ctx = network.WithUseTransient(ctx, "circuit-relay routing")
```

In v0.33, circuit-v2 connections are tagged "limited"/"transient" and
`NewStream` refuses to use them by default. Pre-bump (v0.8) the concept
didn't exist; relayed connections were treated identically to direct
ones. Without this opt-in, `NewStream` silently blocks waiting for a
non-transient connection that never appears.

**`dht/dhtclient/dhtclient.go::RouteEnvelope` — two-step Connect:**

The old code constructed `/p2p/<source-relay>/p2p-circuit/p2p/<target>`
and dialed it directly. That works for the same-relay topology (which
is the dominant real-world case) but is wrong when the target is
reserved with a different relay. The v0.33 setup tries the source-relay
path first with a 5-second timeout, then falls back to a peer-ID-only
`Connect` so routedhost's DHT-based peer routing can discover the
target's actual circuit address. Pre-bump this fan-out happened
transparently inside `EnableRelay`'s auto-relay machinery; in v0.33 we
spell it out.

### Internal context

See the chore commits prefixed `chore(libp2p_node):` and `fix(libp2p_node):`
in the `feat/libp2p-bump-cleanup` branch history (PR #872) for the
migration commits, and the `Deferred / still open after this pass` section
of `CLEANUP.md` at the repo root for any remaining follow-ups.
