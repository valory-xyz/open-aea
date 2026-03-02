# AEA Framework Audit

Comprehensive audit of the open-aea codebase. Date: 2026-02-28.

## Production-Relevant Issues

### P1. CRITICAL — `connection_exception_policy` silently ignored ✅

`aea/aea.py:133,174` — The policy is stored in `self._connection_exception_policy` but never passed into `multiplexer_options`. The multiplexer always falls back to `propagate`, regardless of user config (`just_log`, `stop_and_exit`).

### P2. CRITICAL — `FSMBehaviour` final state detection broken ✅

`aea/skills/behaviours.py:360` — `current_state in self._final_states` compares a `State` object to a `Set[str]`. This never matches, so the FSM can never detect reaching a final state.

### P3. CRITICAL — `TickerBehaviour.last_act_time` returns wrong value ✅

`aea/skills/behaviours.py:148` — Returns `self._start_at` instead of `self._last_act_time`. Any code inspecting when the behaviour last acted gets the start time instead.

### P4. CRITICAL — `asyncio.StreamReader(loop=)` removed in Python 3.10 ✅

`aea/helpers/pipe.py:173-175` — The `loop=` parameter was removed in Python 3.10. This causes `TypeError` at runtime on all supported Python versions when `PosixNamedPipeProtocol.connect()` is called.

### P5. CRITICAL — `asyncio.ensure_future(loop=)` removed in Python 3.10 ✅

`aea/manager/manager.py:233-234` — Same as above. `AgentRunProcessTask.start()` will crash at runtime on all supported Python versions.

### P6. HIGH — Default connection validation always passes ✅

`aea/multiplexer.py:138-146` — `bool([...])` checks if the list is non-empty (always True if connections exist), not whether any element matched. Should use `any(...)`. An invalid default connection passes validation silently.

### P7. HIGH — `install_dependencies` uses wrong pip flag ✅

`aea/helpers/install_dependency.py:71` — Replaces `-i` with `--extra-index`, but the correct pip flag is `--extra-index-url`. This causes pip to error on multi-dependency installs with custom indexes.

### P8. HIGH — `merge_dependencies` checks wrong variable ✅

`aea/configurations/pypi.py:256` — `old_dep_is_simple = is_simple_dep(info)` checks the **new** dependency instead of the old one. This inverts the merge logic, potentially allowing invalid merges or rejecting valid ones.

### P9. HIGH — Single connection failure kills entire receiving loop ✅

`aea/multiplexer.py:532` — `task.result()` in `_receiving_loop` re-raises exceptions from any connection's `receive()`. The outer `except` terminates the loop for **all** connections, not just the failing one.

### P10. INFO — `remove_unused_component_configurations` config dump placement

`aea/cli/remove.py:300-301` — The `open_file`/`dump` code sits after the `@contextmanager` generator's `finally` block, so it only runs on success. This is intentional: on failure no items were removed, so no disk write is needed. The `finally` block correctly restores in-memory `component_configurations`. In the rare case of partial failure during dependency removal the disk state may be stale, but moving the dump into `finally` would break existing tests and error handling.

### P11. HIGH — `Dialogue.is_self_initiated` uses identity comparison ✅

`aea/protocols/dialogue/base.py:523-525` — Uses `is not` instead of `!=` on address strings. Python does not guarantee string interning for arbitrary values, so equal addresses may still fail the identity check.

### P12. INFO — `DialogueLabel.from_str` breaks on underscores in fields

`aea/protocols/dialogue/base.py:207-220` — Uses `_` as separator in `__str__` and `split("_")` in `from_str`. Breaks if addresses or references contain underscores. Not fixable without changing `__str__`, which would break backward compatibility with persisted dialogue storage keys. `from_str` is not used in production code (only tests); production serialization uses `from_json`/`json`.

### P13. MEDIUM — `sys.stderr` permanently replaced with `/dev/null` (reverted, intentional)

`aea/cli/run.py:218` — After profiling stops, `stderr` is redirected to `/dev/null` and never restored. This is an intentional hack to suppress faulty garbage collection output printed to stderr during interpreter shutdown. The redirect only takes effect at the very end of the profiling context, so it does not silence meaningful error output during normal execution. The original save-and-restore fix was reverted as it defeated the purpose of the hack.

### P14. MEDIUM — Private keys written with default (world-readable) permissions (deferred)

`aea/crypto/base.py:174` — `open(private_key_file, "wb")` uses default permissions (typically `0o644`). Should use `0o600` for private key files. Deferred: changing file permissions is observable behaviour that could break downstream tooling, CI/CD pipelines, or scripts that read key files as a different user.

### P15. MEDIUM — `AsyncState` not thread-safe (deferred)

`aea/helpers/async_utils.py:65-160` — Used across threads (runtime state changes from async thread, read from main thread) but has no synchronization primitives protecting `_state`, `_watchers`, or `_callbacks`. Deferred: adding locks to this core runtime primitive changes timing behaviour and risks deadlocks or performance regressions. The race condition is real but rarely triggered in practice.

### P16. MEDIUM — Manager shared state modified from multiple threads without locks (deferred)

`aea/manager/manager.py` — `_agents`, `_agents_tasks`, `_projects` are accessed from both main thread and background event loop thread with no lock protection. Can cause `RuntimeError: dictionary changed size during iteration`. Deferred: adding mutexes could cause deadlocks if existing code holds other locks or does blocking calls while iterating. The race condition is real but rarely triggered in practice.

### P17. MEDIUM — `_wait_for_result` crashes on `queue.Empty` ✅

`aea/manager/manager.py:242-254` — `get_nowait()` is called immediately after detecting process is dead, but the result may not yet be in the queue. Unhandled `queue.Empty` exception.

### P18. MEDIUM — `PosixNamedPipeProtocol` leaks file descriptors on retry ✅

`aea/helpers/pipe.py:157-166` — When output pipe open fails with `ENXIO`, the input file descriptor from line 157 is never closed before recursing to retry. Each retry leaks a file descriptor. Fix: close the previous input `fd` when a new one is opened on retry (not immediately on ENXIO), because named pipes require the read end to stay open for the other side to connect its write end.

### P19. MEDIUM — `Message.__init__` silently swallows consistency errors (deferred)

`aea/protocols/base.py:86-89` — Consistency check failures are caught and only logged. Invalid messages are created in an inconsistent state with no programmatic way to detect the error. Deferred: raising exceptions instead of logging would break any downstream code that constructs messages with temporarily inconsistent fields. The current log-and-continue behaviour is almost certainly relied upon.

### P20. MEDIUM — `re.match` for class name lookup allows partial/regex matches ✅

`aea/connections/base.py:294`, `aea/contracts/base.py:131`, `aea/protocols/base.py:393,404`, `aea/skills/base.py:766` — Class names from config are used as regex patterns with `re.match`, which doesn't require a full match. `"MyConn"` would match `"MyConnection"`. Fixed across all four component types (connections, contracts, protocols, skills). Customs are config-only and have no class loading.

### P21. MEDIUM — `MixedRegistry.check_item_present` missing early return ✅

`aea/cli/publish.py:273-293` — After successful local check, no `return` statement. Falls through to remote check. If remote registry is down but package exists locally, publish fails with misleading error.

### P22. INFO — `ItemSpec.get_class` mutates class objects via `setattr`

`aea/crypto/registries/base.py:149-158` — Every call to `get_class()` sets class-level attributes via `setattr` on the original class. If two `ItemSpec` instances reference the same class with different `class_kwargs`, the last call wins. In practice this does not occur: crypto plugins register distinct classes, and contracts have a re-registration guard. Fixing this (e.g. via dynamic subclassing) would change `type(instance) is OriginalClass` identity checks, breaking downstream code that relies on exact type matching. Left as-is for consistency and backward compatibility.

### P23. MEDIUM — No thread safety in component registries ✅

`aea/registries/base.py:337-367` — Non-atomic read-unregister-modify-register pattern with no locking. Dynamic component registration can lose updates under concurrent access.

### P24. INFO — `ProtectedQueue.put` ignores caller-supplied `block` and `timeout`

`aea/decision_maker/base.py:182` — Hard-codes `block=True, timeout=None` regardless of caller arguments. Likely intentional: the `ProtectedQueue` ensures messages between skills and the decision maker are never silently dropped. The method signature is misleading (accepts `block`/`timeout` but ignores them), but changing the behaviour risks dropping messages in production. `put_nowait` exists as a separate path for non-blocking puts.

### P25. LOW — `BaseException` catch converts Ctrl-C to ClickException (deferred)

`aea/cli/remove.py:425` — Makes it impossible to interrupt a removal operation with Ctrl-C. Deferred: changing exception handling flow in CLI commands could affect downstream error handling, exit codes, or cleanup logic.

### P26. LOW — `Dependency.from_json` does not preserve `extras` (deferred)

`aea/configurations/data_types.py:937-953` — `extras` not in `allowed_keys`. Round-tripping through JSON loses extras information. Deferred: adding `extras` to serialization changes output that downstream tools may parse or compare, and could affect package hash generation.

## Developer Experience Issues

### D1. HIGH — `logging.getLogger(__file__)` instead of `__name__` ✅

`aea/helpers/async_utils.py:48`, `aea/helpers/profiling.py:45`, `aea/helpers/exec_timeout.py:35` — Creates logger names like `/Users/.../async_utils.py` instead of `aea.helpers.async_utils`. Breaks the standard Python logging hierarchy — configuring logging for `aea.helpers` won't affect these loggers.

### D2. HIGH — Imports from private `concurrent.futures._base` ✅

`aea/runtime.py:24`, `aea/multiplexer.py:26-27` — Importing `CancelledError` and `TimeoutError` from a private module risks breakage in future Python versions. Replaced with `asyncio.CancelledError` and `asyncio.TimeoutError` (same classes since Python 3.9+).

### D3. HIGH — `suppress(Exception, asyncio.CancelledError)` swallows all errors during shutdown ✅

`aea/multiplexer.py:365-366, 377-378` — All exceptions were silently swallowed with no logging. Replaced with explicit try/except that passes on `CancelledError` (expected during shutdown) but logs other exceptions via `logger.exception`.

### D4. HIGH — `resp_json["detail"]` crashes on HTTP 500 with non-JSON body ✅

`aea/cli/registry/utils.py:103-117` — If server returns 500 with non-JSON body, `resp_json` is `None` and `resp_json["detail"]` raises `TypeError` instead of a meaningful error. Also fixed same pattern for 409 responses.

### D5. MEDIUM — 17+ uses of deprecated `asyncio.get_event_loop()` (deferred)

Multiple files — Emits `DeprecationWarning` on Python 3.10+ when no running loop exists. Should use `asyncio.get_running_loop()` in async contexts or explicit `asyncio.new_event_loop()` elsewhere. Deferred: scattered across many files, each call site needs individual analysis (async vs sync context). High chance of subtle regressions.

### D6. MEDIUM — `inspect.stack()` called on every `PersistDialoguesStorage.__init__` (deferred)

`aea/protocols/dialogue/base.py:1057-1068` — Expensive operation that captures all frames and prevents garbage collection of local variables. Performance bottleneck with many dialogues. Deferred: fixing requires passing the skill component explicitly rather than inspecting the stack, which changes the constructor's public API.

### D7. MEDIUM — Class-level mutable defaults in `BaseAEATestCase` (deferred)

`aea/test_tools/test_cases.py:120-135` — `subprocesses`, `threads`, `agents` are shared mutable class defaults. Can leak between test classes if setup/teardown discipline isn't followed. Deferred: changing to instance-level initialization could break subclasses in downstream projects that access these before setup runs or override them at class level.

### D8. MEDIUM — `asyncio.Queue()` outside event loop in `BaseSkillTestCase` (deferred)

`aea/test_tools/test_skill.py:507-509` — Deprecated in Python 3.10+. Emits warnings or fails in newer Python versions. Deferred: this is in test tooling used by downstream projects. Changing queue creation could break test setup patterns in dependent projects.

### D9. INFO — `_load_state` breaks on first project failure

`aea/manager/manager.py:1072-1093` — Uses `break` instead of `continue` when a project fails to load, skipping remaining projects. Likely intentional fail-fast behaviour: subsequent projects may depend on the failed one, and continuing could cause cascading errors or inconsistent state. The `failed_to_load` list is returned to the caller to handle.

### D10. MEDIUM — `_set_executor_pool` ignores its `max_workers` parameter ✅

`aea/connections/base.py:380-388` — Parameter immediately overwritten by config value on the next line. Fixed to use `max_workers` as fallback when config does not specify `max_thread_workers`.

### D11. LOW — Dead code: Python < 3.7 compatibility branches ✅

`aea/protocols/dialogue/base.py:55-70` — Unreachable since the project requires Python 3.10+. Removed branch, kept only the Python 3.7+ path. Also removed unused `sys` import.

### D12. LOW — Typos in code ✅ (partial)

- `aea/multiplexer.py:133` — `"os out of"` → `"is out of"` ✅
- `aea/multiplexer.py:235` — `"multipelxer"` → `"multiplexer"` ✅
- `aea/cli/utils/exceptions.py:30` — Function `aev_flag_depreaction` → `aev_flag_deprecation`; message `"envrionment varibales"` → `"environment variables"` ✅
- `aea/configurations/manager.py:356` — `substitude_env_vars` should be `substitute_env_vars`. Deferred: public API parameter used extensively across codebase, tests, and docs. Breaking to rename.

### D13. LOW — Stale deprecation warning claims removal in v2.0.0 ✅

`aea/cli/utils/exceptions.py:30-33` — Removed the stale "will be removed in v2.0.0" version reference from the deprecation message.

### D14. LOW — `clean_tarfiles` removes ALL `.tar.gz` files in CWD (deferred)

`aea/cli/registry/utils.py:238-259` — Not scoped to the file created by the decorated function. Deferred: scoping it could break if the decorated function creates multiple tar files or relies on cleanup of pre-existing files.

### D15. LOW — Copy-paste docstring errors ✅

`aea/skills/base.py:658-665` — Both `behaviours` and `models` properties said "Get the handlers." Fixed to "Get the behaviours." and "Get the models." respectively.

### D16. LOW — `--aev` flag value hard-coded to `True` (deferred)

`aea/cli/run.py:156` — `--aev` flag exists on CLI but `apply_environment_variables` is always passed as `True`. Misleading interface. Deferred: removing the flag or making it functional changes CLI behaviour that downstream tools may depend on.

### D17. LOW — `AgentRunProcessTask._run_agent` — `aea` may be unbound in finally ✅

`aea/manager/manager.py:269-303` — If `get_aea_instance()` raises, `aea.logger.debug(...)` in the finally block causes `NameError`. Added guard to check `"aea" in locals()` before accessing.
