# Connection resilience

Framework-developer guidance for choosing retry and timeout behaviour when extending or adding to AEA. The aim is not to standardise every component on one policy — different operations have different correctness requirements — but to give contributors a shared mental model for where to put a retry, where to put a timeout, and where to surface a failure instead of swallowing it. Reads alongside the architectural overviews in [Design principles](./design-principles.md) and [Architectural diagram](./diagram.md), and the per-component pages on [Skills](./skill.md), [Connections](./connection.md), and [Protocols](./protocol.md); message-flow background lives in [Message routing](./message-routing.md).

## Where work happens in an agent

Three component types co-operate around any external interaction.

**[Skills](./skill.md)** carry the operation's *semantics*. A skill knows whether the thing it just asked for is idempotent, whether it can be retried at all, whether a partial failure is acceptable, and what to do next when an attempt fails (resubmit, escalate, give up, switch strategy). Skills are the right layer for retry decisions that depend on what the operation means in the agent's domain.

**[Connections](./connection.md)** carry the *transport*. A connection knows about the network stack underneath it: TCP, TLS, an RPC pool, a P2P fabric, an HTTP server. It knows what "the daemon is unreachable" looks like and can classify transport failures (rate-limit, DNS, reset, timeout). It does *not* know whether the request is safe to repeat — only the skill does.

**[Protocols](./protocol.md)** define the *speech acts* between the two (the set of message types and the reply rules between them; speech acts are also called performatives in FIPA-derived terminology, and they live under the `speech_acts:` key in any `protocol.yaml`). That set decides how rich the skill's failure signal is, which in turn shapes how much of the retry decision-making the skill can do. A protocol that exposes a typed `error` performative on every initiation gives the connection an explicit channel to surface failures back to the skill — the skill can then react to the failure type as a typed message. A protocol that defines only a request/response pair (no `error` performative) forces the connection to absorb or reflect failures into the response shape, because there is no other way to honour the dialogue contract. Both layers can still retry internally in either model; what changes is whether the skill sees failures as failures or has to detect them by parsing the success-shaped reply.

## What the protocol's speech acts imply

Walking through the protocols actually in the repo makes the boundary concrete.

**Typed-error protocols → skill sees failures as failures.** [`valory/ledger_api`](../packages/valory/protocols/ledger_api/README.md) declares an `error: {code, message, data}` performative and every initiation maps to either the typed success reply or `error` (e.g. `get_balance: [balance, error]`, `send_signed_transaction: [transaction_digest, error]`). The connection is free to retry internally — the ledger dispatcher retries up to its configured budget with bounded backoff before giving up — but when it does give up the skill receives an explicit `error` message and can route on the failure type (escalate, switch strategy, re-initiate later). The protocol even lets the skill cap the dispatcher's internal retry loop via the optional `retry_timeout` / `retry_attempts` parameters on `get_transaction_receipt`. The combined effect is that retry semantics are layered: the connection retries transport faults inside its budget; the skill retries (or escalates) at the dialogue level when that budget is exhausted. [`valory/contract_api`](../packages/valory/protocols/contract_api/README.md) follows the same shape (`get_state`, `get_raw_transaction`, `get_raw_message`, `get_deploy_transaction` all reply with either the typed success or `error`).

**Status-with-classification protocols → skill sees failures with rich signal.** [`valory/acn`](../packages/valory/protocols/acn/README.md) replies to `register` and `aea_envelope` with a `status` message carrying a `StatusCodeEnum` (`SUCCESS`, `ERROR_UNKNOWN_AGENT_ADDRESS`, `ERROR_AGENT_NOT_READY`, etc.), and replies to `lookup_request` with either `lookup_response` or `status`. The protocol surfaces *which* failure happened, not just *that* it happened, so the skill can implement retry-by-category (e.g. "retry on `ERROR_AGENT_NOT_READY` but not on `ERROR_INVALID_PROOF`"). [`open_aea/signing`](../packages/open_aea/protocols/signing/README.md) is the same idea applied to the [decision-maker](./decision-maker.md) side: `sign_transaction` / `sign_message` reply with the signed payload or an `error` carrying `UNSUCCESSFUL_MESSAGE_SIGNING` / `UNSUCCESSFUL_TRANSACTION_SIGNING`. Signing failures are rarely retry-worthy, so in practice the skill escalates, but the protocol shape still gives the skill a typed signal to act on.

**Response-only protocols → connection absorbs (or reflects).** [`valory/http`](../packages/valory/protocols/http/README.md) defines only `request` and `response`, with `reply: request: [response]`. There is no `error` performative. The connection therefore *must* answer every `request` with a `response` — it has no other speech act in the dialogue. The `http_client` connection's policy is "don't retry, reflect": transport failures (unreachable, timeout, SSL) are flattened into a synthetic `response` with `status_code=600` and the traceback in the body, and the skill is left to parse the status code and decide. This is the canonical case of "protocol shape forces a response, connection absorbs the failure into it." A future connection could legitimately switch to "retry once, then reflect" without changing the protocol — the speech-acts list doesn't constrain that choice, but it does constrain the *shape* of the answer.

**Routing-failure protocols → no retry, surfaces internal bugs.** [`fetchai/default`](../packages/fetchai/protocols/default/README.md) is the framework's fallback channel for routing-layer failures. When an envelope arrives that can't be decoded or routed, the `fetchai/error` skill (the dedicated error-handler skill an agent includes in its configuration; see [`packages/fetchai/skills/error/handlers.py`](../packages/fetchai/skills/error/handlers.py)) constructs a `DefaultMessage` with one of the error codes (`UNSUPPORTED_PROTOCOL`, `DECODING_ERROR`, `INVALID_MESSAGE`, `UNSUPPORTED_SKILL`, `INVALID_DIALOGUE`) and sends it back to the originator. These are within-agent failures by definition; retrying them masks bugs. The protocol's existence is what makes the framework's "surface routing failures, don't crash the loop" stance implementable.

The pattern across all of these: **the protocol's `speech_acts` and reply rules are the contract that decides how rich a failure signal the skill receives, and therefore what the skill can choose to do about it.** Adding an `error` performative gives the skill an explicit channel for "the call failed and here is why"; omitting it forces any failure into the success-shaped response (or no response at all). Both layers can still retry internally, but the protocol shape decides whether the skill can make typed decisions or has to detect failure by parsing. Decide consciously at the protocol-design stage rather than at the connection-implementation stage.

## Within-agent failures vs agent-to-external failures

The framework treats two failure classes very differently.

**Within-agent failures** are bugs in the code we ship: a connection handler raising unexpectedly, a skill misconfiguring a dialogue, a protocol message that fails to decode. The framework's stance is to *surface these immediately*. Connections are expected to catch their own exceptions and emit an error envelope over the originating protocol's `error` performative when one exists; routing-layer failures (an envelope that can't be decoded or matched to a protocol; see [Message routing](./message-routing.md) for how envelopes flow through the agent) are surfaced separately by the `fetchai/error` skill via [`fetchai/default`](../packages/fetchai/protocols/default/README.md). The multiplexer logs anything that escapes and keeps the loop alive so one misbehaving connection can't take the agent down. Retrying these is almost always wrong — the state didn't drift, the code did. Fix it or fail loudly.

**Agent-to-external failures** are everything beyond the agent's process boundary: an RPC node going dark, an IPFS gateway returning a CDN error page, a gas-price API drifting its schema, a peer dropping a connection. The framework's stance is to *bound the impact*. The connection retries transport failures within a bounded budget (where the protocol allows it to), the skill makes the call about whether to give up or change strategy, and the timeout values are sized so an operator can correlate "agent gave up" with "outage on this external dependency" in the time it took.

When choosing a policy, the first question is which class of failure you are designing for. Retrying within-agent failures masks bugs; bailing out instantly on external failures wastes the agent's only recourse.

## Why policies differ

Even within agent-to-external failures, three properties drive the shape of any given policy.

1. **Idempotency.** A read query (`get_balance`, `get_transaction_receipt`) can be retried freely. A write transaction (`eth_sendRawTransaction`) cannot — once the network has accepted the transaction its state is unknown to the caller, and most networks reject or drop a duplicate-nonce resubmission rather than process it twice. The risk is not so much "double-spend" as "we don't know which broadcast won, and now we're acting on stale information." Code at the connection layer that retries writes silently is a bug, not a feature. Resubmission, if it's the right call, belongs in the skill, which knows what to check first.
2. **Caller layer.** Whether a retry belongs in the connection, the underlying client library, or the skill depends on which layer has the information needed to decide. The connection knows about transport faults; the client library may know about RPC-level semantics; only the skill knows about the operation's meaning. Put the retry at the lowest layer that has *all* the information needed to be safe — and remember that the protocol shape (see above) may already have pinned the answer.
3. **Time budget.** A loop that waits "forever" is rarely correct. An operator looking at the agent during an outage should be able to tell that work has given up, not still trying — bounded backoff makes outages observable, and surface-back-to-skill makes them actionable. The right size depends on the operation's timeline (block time, mempool churn, daemon restart cadence), not on a single global default.

## Per-component overview

### HTTP client connection

[`packages/valory/connections/http_client`](../packages/valory/connections/http_client/connection.py). Speaks [`valory/http`](../packages/valory/protocols/http/README.md). No retries; one attempt per request. The whole call is wrapped in `asyncio.wait_for(timeout=self.timeout)` (default 300s, configurable per request). Unreachable, timeout, and other transport failures are flattened to a `response` envelope with status code 600 and the traceback in the body, so the caller's skill has to make the retry decision based on the operation it's performing. The protocol has no `error` performative; this is what "connection reflects, skill decides" looks like in practice.

### HTTP server connection

[`packages/valory/connections/http_server`](../packages/valory/connections/http_server/connection.py). No retries on the inbound side. The handler dispatch is wrapped in `asyncio.wait_for(timeout=timeout_window)` (default 5s). If the skill response doesn't arrive in time, the client receives HTTP 408 and the queue entry is cleaned up. Inbound retries are the *client's* job; the agent's job is to bound the time it spends holding a connection.

### Ledger connection (read-side)

[`packages/valory/connections/ledger`](../packages/valory/connections/ledger/connection.py). Speaks [`valory/ledger_api`](../packages/valory/protocols/ledger_api/README.md). `get_transaction_receipt` and `get_transaction` retry up to the configured `retry_attempts` times (see the `retry_attempts` key in `connection.yaml` for the shipped default) with a linear backoff `retry_timeout * attempts`. Each individual sleep is capped at `MAX_RETRY_DELAY` so the per-attempt wait does not grow unboundedly across the budget; the cap bounds the worst-case loop while preserving the retry count, so a sustained RPC outage gives up in a time an operator can correlate with the outage window. The single-attempt timeout is enforced by `asyncio.wait_for` inside `RequestDispatcher.wait_for`. When the budget is exhausted, the dispatcher replies with the protocol's `error` performative and the skill decides whether to re-initiate.

### Ledger connection (write-side)

`send_signed_transaction` and `send_signed_transactions` do not retry. Once the transaction has been transmitted to the network the connection no longer has the information needed to decide what to do next: the broadcast may have been accepted, dropped, or queued in some node's mempool. Resubmission is the skill's responsibility — the skill is expected to check the receipt via the read-side path before deciding to re-submit, and to do so under its own nonce-management discipline. The connection's job is to report what happened and stop. The protocol's `error` performative on `send_signed_transaction` is exactly the slot the connection uses to do so.

### Ledger connection thread pool

The connection runs all dispatcher work in a dedicated `ThreadPoolExecutor` sized by the `max_thread_workers` config (see `connection.yaml` for the shipped default). This isolates ledger calls from Python's default asyncio executor so retry threads inside `RotatingHTTPProvider.make_request` cannot consume threads shared with the rest of the agent. Operators expecting high ledger concurrency (multiple skills issuing reads while a write is in flight) should raise `max_thread_workers` to comfortably exceed peak concurrent retries for the deployment's RPC topology.

Pool sizing interacts with the dispatcher's retry budget: a single in-flight request can occupy a worker thread until its retry sequence finishes, so worst-case occupancy per slot is `retry_attempts × min(retry_timeout × attempts, MAX_RETRY_DELAY)`. With `max_workers` slots full, new submissions queue on `loop.run_in_executor(...)` and the connection appears hung even though the dispatchers are still spinning. Two practical consequences. `LedgerApiRequestDispatcher` and `ContractApiRequestDispatcher` share the same executor, so ledger-side retries can starve contract-side traffic and vice versa. And now that `RotatingHTTPProvider` exists in the ethereum plugin and handles transport-layer rotation/backoff per call, the shipped `retry_attempts` default is a layered backstop rather than the primary retry mechanism — keep the value tight (the shipped default is 60) and lean on the provider for short-term transport faults; raise it only if you've removed the provider layer or have a ledger where it doesn't apply.

### `RotatingHTTPProvider`

[`plugins/aea-ledger-ethereum/aea_ledger_ethereum/rpc_rotation.py`](../plugins/aea-ledger-ethereum/aea_ledger_ethereum/rpc_rotation.py). Switches between RPC URLs on transport failure with per-endpoint health tracking and bounded exponential backoff (see `RETRY_DELAY` and `MAX_RETRY_DELAY` in `rpc_rotation.py` for the constants in effect). The retry budget is `min(MAX_RETRIES, url_count * 2)` so single-RPC deployments retry at most twice. Write methods (`eth_sendRawTransaction`, `eth_sendTransaction`) are retried only on clear pre-send failures (`connection`, `fd_exhaustion`) so a partially submitted transaction is never re-broadcast. The provider uses `time.sleep` between retries because web3 transports are synchronous; see the class docstring for the interaction with the ledger connection's thread pool.

### IPFS client

[`plugins/aea-cli-ipfs/aea_cli_ipfs/ipfs_client.py`](../plugins/aea-cli-ipfs/aea_cli_ipfs/ipfs_client.py). The HTTP wrapper makes one attempt per call with a fixed timeout. Retries are the caller's responsibility; the higher-level `ipfs_utils.download()` wraps client calls with a small retry loop on `StatusError`. The success-path `json.loads` calls route through `_safe_json_loads`, which raises a typed `StatusError` on non-JSON 200 responses so retryable transient failures (e.g. a CDN error page slipping through) surface as the same error class as other status failures and the caller's retry loop sees them. The error message preview is truncated and stripped of non-printable bytes so an arbitrary remote response cannot inject terminal-control sequences into operator logs.

### P2P libp2p

[`packages/valory/connections/p2p_libp2p`](../packages/valory/connections/p2p_libp2p). Speaks the routing side of [`valory/acn`](../packages/valory/protocols/acn/README.md). Reconnect-on-failure with a bounded number of inline attempts (`connect_retries`, default 3). Pipe connection has an explicit 10s timeout (`PIPE_CONN_TIMEOUT`). ACN acknowledgements time out at 5s (`ACN_ACK_TIMEOUT`). The connection talks to a Go subprocess via IPC, so the failure surface here is "local node misbehaviour" rather than "network outage."

### P2P libp2p client

[`packages/valory/connections/p2p_libp2p_client`](../packages/valory/connections/p2p_libp2p_client). Per-envelope resend budget capped by `resend_envelope_retry` (default 1, configurable). Linear sleep between connect attempts (max ~10–15s on three retries).

### P2P libp2p mailbox

[`packages/valory/connections/p2p_libp2p_mailbox`](../packages/valory/connections/p2p_libp2p_mailbox). Polling read loop sleeps `NO_ENVELOPES_SLEEP_TIME` (currently 2s) between empty responses. Send path tries once and reconnects-and-retries once on failure.

### Cosmos / Fetchai / Solana ledger plugins

Direct `requests.get/post` calls in the cosmos plugin use a 60s timeout (`NETWORK_REQUEST_DEFAULT_TIMEOUT`). The `RestClient` used by the underlying `cosmpy` library inherits its own default; the plugin does not currently surface a timeout knob. The Solana plugin similarly uses the `solana.rpc.api.Client` default. Both are acceptable for typical deployments; surface a timeout knob if you need tighter bounds. See [Ledger & Crypto APIs](./ledger-integration.md) for how plugin selection and ledger configuration plug into the connection.

## Picking a policy for a new component

When you add a new connection, a new ledger plugin, or a new external integration, walk this checklist before writing the retry loop.

1. **Which failure class am I designing for?** A within-agent bug or an agent-to-external failure. If it's the first, surface fast and loudly; if it's the second, bound the impact.
2. **What do the protocol's speech acts say?** If the dialogue defines an `error` (or status-classified) reply, the skill is the natural retry owner — your connection's job is to classify the failure and surface it. If the dialogue only defines a success-shaped reply, the connection is the only layer that can act and must absorb or reflect transport failures into that single response shape.
3. **Which layer owns the *semantic* decision?** The skill owns retry policy for anything semantic (idempotency, nonce management, partial-failure recovery). The connection owns retry policy for transport faults it can classify itself, *only when the protocol allows it to retry transparently*. If the right answer is "the caller knows better than I do," surface a typed error envelope and let the skill decide.
4. **Is the operation idempotent at the *external* boundary?** Not "idempotent in our code", but "idempotent at the remote system". If not, never retry silently — surface the failure and let the skill check state before re-submitting.
5. **Bound everything.** Per-attempt timeout, total backoff, and pool size should all have explicit upper bounds. "Infinite polling" is acceptable only when it *is* the operation (e.g. mailbox `read_envelope`).
6. **Document the worst case.** A reader of the component's docstring should be able to answer "if this dependency is down for an hour, what does the agent do?" without tracing the code. If they can't, the docstring is incomplete.
7. **Log the type, not just the message.** A swallowed exception that logs only `str(e)` ("`maxFee`") tells an operator nothing. Use `type(e).__name__: str(e)` (or equivalent structured fields) so transport failures and schema drift are distinguishable in the logs.
