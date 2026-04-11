
The <a href="../api/manager/manager">`MultiAgentManager`</a> allows managing multiple agent projects programmatically.

## Setup

We instantiate the manager by providing it with the working directory in which to operate and starting it:

``` python
import os
from pathlib import Path
from aea.manager import MultiAgentManager

WORKING_DIR = "mam"

manager = MultiAgentManager(WORKING_DIR)
manager.start_manager()
```

## Adding projects

We first add a couple of finished AEA projects. Replace the placeholders below with the public ids of the agent projects you want to manage:

``` python
from aea.configurations.base import PublicId

first_agent_id = PublicId.from_str("your_author/your_first_agent:0.1.0")
second_agent_id = PublicId.from_str("your_author/your_second_agent:0.1.0")
manager.add_project(first_agent_id, remote=True)
manager.add_project(second_agent_id, remote=True)
first_agent_name = first_agent_id.name
second_agent_name = second_agent_id.name
```

## Adding agent instances

Add the agent instances, wiring each to a `valory/p2p_libp2p:0.1.0` connection for ACN transport:

``` python
p2p_public_id = PublicId.from_str("valory/p2p_libp2p:0.1.0")

agent_overrides = {
    "private_key_paths": {"ethereum": "ethereum_private_key.txt"},
    "connection_private_key_paths": {
        "ethereum": "ethereum_connection_private_key.txt",
        "cosmos": "cosmos_connection_private_key.txt",
    },
}

component_overrides = [{
    **p2p_public_id.json,
    "type": "connection",
    "cert_requests": [{
        "identifier": "acn",
        "ledger_id": "ethereum",
        "not_after": "2027-01-01",
        "not_before": "2026-01-01",
        "public_key": "cosmos",
        "message_format": "{public_key}",
        "save_path": ".certs/conn_cert.txt",
    }],
}]
manager.add_agent(first_agent_id, component_overrides=component_overrides, agent_overrides=agent_overrides)

# Second agent: same pattern, plus `config` overrides so the two libp2p
# nodes don't try to bind the same ports when running on one host.
component_overrides = [{
    **p2p_public_id.json,
    "type": "connection",
    "config": {
        "delegate_uri": "127.0.0.1:11001",
        "entry_peers": ["/dns4/127.0.0.1/tcp/9000/p2p/16Uiu2HAkzgZYyk25XjAhmgXcdMbahrHYi18uuAzHuxPn1KkdmLRw"],
        "local_uri": "127.0.0.1:9001",
        "public_uri": "127.0.0.1:9001",
    },
    "cert_requests": [{
        "identifier": "acn",
        "ledger_id": "ethereum",
        "not_after": "2027-01-01",
        "not_before": "2026-01-01",
        "public_key": "cosmos",
        "message_format": "{public_key}",
        "save_path": ".certs/conn_cert.txt",
    }],
}]

manager.add_agent(second_agent_id, component_overrides=component_overrides, agent_overrides=agent_overrides)
```

Save the private keys into the files referenced above. `valory/p2p_libp2p:0.1.0` needs three keys: an `ethereum` key for the agent identity and for signing the ACN certificate, a `cosmos` key used as the libp2p node identity, and an `ethereum` connection key (which is the same file as the agent key or a separate one, as you prefer). You can generate them with `aea generate-key` or write deterministic test keys programmatically, for example:

``` python
ETH_PRIVATE_KEY_FIRST = b"<hex-encoded ethereum private key>"
ETH_PRIVATE_KEY_PATH_FIRST = Path(manager.data_dir, first_agent_name, "ethereum_private_key.txt").absolute()
ETH_PRIVATE_KEY_PATH_FIRST.write_bytes(ETH_PRIVATE_KEY_FIRST)

COSMOS_CONNECTION_KEY_FIRST = b"<hex-encoded cosmos private key>"
COSMOS_CONNECTION_KEY_PATH_FIRST = Path(manager.data_dir, first_agent_name, "cosmos_connection_private_key.txt").absolute()
COSMOS_CONNECTION_KEY_PATH_FIRST.write_bytes(COSMOS_CONNECTION_KEY_FIRST)

# ... and similarly for `second_agent_name`.
```

## Running the agent instances

``` python
import time

manager.start_agent(first_agent_id.name)

# wait for ~10 seconds for the first peer node to go live
time.sleep(10.0)

manager.start_agent(second_agent_id.name)

time.sleep(5.0)
```

## Stopping the agent instances

``` python
manager.stop_all_agents()
```

## Cleaning up

``` python
manager.stop_manager()
```

# Limitations

The `MultiAgentManager` can only be used with compatible package versions, in particular the same package (with respect to author and name) cannot be used in different versions. If you want to run multiple agent instances with differing versions of the same package then use the `aea launch` command in the multi-processing mode, or simply launch each agent instance individually with `aea run`.
