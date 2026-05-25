<a id="aea.helpers.logging"></a>

# aea.helpers.logging

Logging helpers.

<a id="aea.helpers.logging.setup_logger"></a>

#### setup`_`logger

```python
def setup_logger(name: str,
                 level: int = logging.INFO,
                 log_format: str = DEFAULT_FORMAT) -> Logger
```

Set up the logger.

Public helper retained for downstream callers in open-autonomy
(``chain/tx.py``, ``analyse/service.py``, and
``plugins/aea-helpers/aea_helpers/bump_dependencies.py``). The in-repo
call in ``aea/helpers/protocols.py`` was removed in `914` because
``logging.basicConfig`` at module-import time pollutes the root logger
and produces duplicate agent log lines under ``aea -s run``. New
in-repo callers should prefer ``logging.getLogger(name)`` directly.

**Arguments**:

- `name`: logger name.
- `level`: log level.
- `log_format`: format string passed to ``logging.basicConfig``.

**Returns**:

the configured logger.

<a id="aea.helpers.logging.get_logger"></a>

#### get`_`logger

```python
def get_logger(module_path: str, agent_name: str) -> Logger
```

Get the logger based on a module path and agent name.

<a id="aea.helpers.logging.AgentLoggerAdapter"></a>

## AgentLoggerAdapter Objects

```python
class AgentLoggerAdapter(LoggerAdapter)
```

This class is a logger adapter that prepends the agent name to log messages.

<a id="aea.helpers.logging.AgentLoggerAdapter.__init__"></a>

#### `__`init`__`

```python
def __init__(logger: Logger, agent_name: str) -> None
```

Initialize the logger adapter.

**Arguments**:

- `logger`: the logger.
- `agent_name`: the agent name.

<a id="aea.helpers.logging.AgentLoggerAdapter.process"></a>

#### process

```python
def process(
        msg: Any,
        kwargs: MutableMapping[str,
                               Any]) -> Tuple[Any, MutableMapping[str, Any]]
```

Prepend the agent name to every log message.

<a id="aea.helpers.logging.WithLogger"></a>

## WithLogger Objects

```python
class WithLogger()
```

Interface to endow subclasses with a logger.

<a id="aea.helpers.logging.WithLogger.__init__"></a>

#### `__`init`__`

```python
def __init__(logger: Optional[Logger] = None,
             default_logger_name: str = "aea") -> None
```

Initialize the logger.

**Arguments**:

- `logger`: the logger object.
- `default_logger_name`: the default logger name, if a logger is not provided.

<a id="aea.helpers.logging.WithLogger.logger"></a>

#### logger

```python
@property
def logger() -> Logger
```

Get the component logger.

<a id="aea.helpers.logging.WithLogger.logger"></a>

#### logger

```python
@logger.setter
def logger(logger: Optional[Logger]) -> None
```

Set the logger.

