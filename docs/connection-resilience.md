# Connection resilience

This page documents the retry and timeout strategies used across the framework's
built-in connections and ledger plugins. The aim is not to standardise every
component on one policy — different operations have different correctness
requirements — but to make the existing choices visible and explain why each
one is shaped the way it is.

## Why policies differ

Three properties drive most decisions:

1. **Idempotency.** A read query (`get_balance`, `get_transaction_receipt`)
   can be retried freely. A write transaction
   (`eth_sendRawTransaction`) cannot — a retry after the network has
   accepted the first submission risks double-spending. Code that retries
   indiscriminately is a bug, not a feature.
2. **Caller layer.** Whether retries belong in the connection, the
   underlying client library, or the caller's behaviour depends on which
   layer has the information needed to decide. The connection knows about
   transport faults; the caller knows about the operation's semantics.
3. **Time budget.** A loop that waits "forever" is rarely correct. An
   operator looking at the agent during an outage should be able to tell
   that work has given up, not still trying — bounded backoff makes
   outages observable.

## Per-component overview

### HTTP client connection

`packages/valory/connections/http_client`. No retries; one attempt per
request. The whole call is wrapped in `asyncio.wait_for(timeout=self.timeout)`
(default 300s, configurable per request). Unreachable, timeout, and other
transport failures are flattened to an error envelope with status code 600
and the traceback in the body, so the caller's skill has to make the retry
decision based on the operation it's performing.

### HTTP server connection

`packages/valory/connections/http_server`. No retries on the inbound side.
The handler dispatch is wrapped in `asyncio.wait_for(timeout=timeout_window)`
(default 5s). If the skill response doesn't arrive in time, the client
receives HTTP 408 and the queue entry is cleaned up.

### Ledger connection (read-side)

`packages/valory/connections/ledger`. `get_transaction_receipt` and
`get_transaction` retry up to `retry_attempts` times (default 240) with
a linear backoff `retry_timeout * attempts`, where each individual sleep
is capped at `MAX_RETRY_DELAY = 60.0` seconds. The cap bounds the
worst-case loop to ~110 minutes while preserving the retry count, so a
sustained RPC outage gives up in a time an operator can correlate with
the outage window. The single-attempt timeout is enforced by
`asyncio.wait_for` inside `RequestDispatcher.wait_for`.

### Ledger connection (write-side)

`send_signed_transaction` and `send_signed_transactions` do not retry.
A write transaction that has been transmitted to the network has
unknown status (it may or may not be included in a future block); a
retry would risk double-broadcast. The caller is expected to check
the receipt via the read-side path before deciding to re-submit.

### Ledger connection thread pool

The connection runs all dispatcher work in a dedicated
`ThreadPoolExecutor` sized by the `max_thread_workers` config (default
32). This isolates ledger calls from Python's default asyncio executor
so retry threads inside `RotatingHTTPProvider.make_request` cannot
consume threads shared with the rest of the agent. Operators expecting
high ledger concurrency (multiple skills issuing reads while a write
is in flight) should raise `max_thread_workers` to comfortably exceed
peak concurrent retries.

### `RotatingHTTPProvider`

`plugins/aea-ledger-ethereum/aea_ledger_ethereum/rpc_rotation.py`.
Switches between RPC URLs on transport failure with per-endpoint health
tracking and bounded exponential backoff
(`RETRY_DELAY = 1.0`, `MAX_RETRY_DELAY = 5.0`). The retry budget is
`min(MAX_RETRIES, url_count * 2)` so single-RPC deployments retry at
most twice. Write methods (`eth_sendRawTransaction`,
`eth_sendTransaction`) are retried only on clear pre-send failures
(`connection`, `fd_exhaustion`) so a partially submitted transaction is
never re-broadcast.

The provider uses `time.sleep` between retries because web3 transports
are synchronous. See the class docstring for the interaction with the
ledger connection's thread pool.

### IPFS client

`plugins/aea-cli-ipfs/aea_cli_ipfs/ipfs_client.py`. The HTTP wrapper
makes one attempt per call with a fixed timeout (120s). Retries are the
caller's responsibility; the higher-level `ipfs_utils.download()` wraps
client calls with a small retry loop on `StatusError`. The success-path
`json.loads` calls route through `_safe_json_loads`, which raises a
typed `StatusError` on non-JSON 200 responses so retryable transient
failures (e.g. a CDN error page slipping through) surface as the same
error class as other status failures.

### P2P libp2p

`packages/valory/connections/p2p_libp2p`. Reconnect-on-failure with a
bounded number of inline attempts (`connect_retries`, default 3). Pipe
connection has an explicit 10s timeout (`PIPE_CONN_TIMEOUT`). ACN
acknowledgements time out at 5s (`ACN_ACK_TIMEOUT`).

### P2P libp2p client

`packages/valory/connections/p2p_libp2p_client`. Per-envelope resend
budget capped by `resend_envelope_retry` (default 1, configurable).
Linear sleep between connect attempts (max ~10–15s on three retries).

### P2P libp2p mailbox

`packages/valory/connections/p2p_libp2p_mailbox`. Polling read loop
sleeps 2s between empty responses (`NO_ENVELOPES_SLEEP_TIME`). Send
path tries once and reconnects-and-retries once on failure.

### Cosmos / Fetchai / Solana ledger plugins

Direct `requests.get/post` calls in the cosmos plugin use a 60s timeout
(`NETWORK_REQUEST_DEFAULT_TIMEOUT`). The `RestClient` used by the
underlying `cosmpy` library inherits its own default; the plugin does
not currently surface a timeout knob. The Solana plugin similarly
uses the `solana.rpc.api.Client` default. Both are acceptable for
typical deployments; surface a timeout knob if you need tighter bounds.

## Picking a policy for a new connection

1. **What is the operation's idempotency?** If submission has side
   effects on remote state, never retry silently. Make the caller
   re-check before re-submitting.
2. **Who has the information to decide a retry is warranted?** If the
   connection has it (transport classifier, health tracker), retry
   inside the connection with a bounded budget. If only the caller
   knows (a behaviour aware of the operation semantics), surface the
   failure with a typed error envelope and let the caller retry.
3. **Bound everything.** Per-attempt timeout, total backoff, and pool
   size should all have explicit upper bounds. "Infinite polling" is
   acceptable only when it's the entire purpose of the loop
   (e.g. mailbox `read_envelope`).
4. **Document the worst case.** A maintainer should be able to read
   the docstring and answer "if this RPC is down for an hour, what
   does the agent do?" without tracing the code.
