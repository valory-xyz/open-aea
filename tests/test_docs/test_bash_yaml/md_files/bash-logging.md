``` bash
aea create my_aea
cd my_aea
```
``` yaml
agent_name: my_aea
author: your_author_handle
version: 0.1.0
license: Apache-2.0
description: ''
aea_version: '>=2.0.0, <3.0.0'
fingerprint: {}
fingerprint_ignore_patterns: []
connections: []
contracts: []
protocols:
- open_aea/signing:1.0.0
skills: []
default_connection: null
default_ledger: ethereum
required_ledgers:
- ethereum
default_routing: {}
connection_private_key_paths: {}
private_key_paths: {}
logging_config:
  disable_existing_loggers: false
  version: 1
dependencies:
  open-aea-ledger-ethereum: {}
```
``` yaml
logging_config:
  version: 1
  disable_existing_loggers: False
  formatters:
    standard:
      format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
  handlers:
    logfile:
      class: logging.FileHandler
      formatter: standard
      level: DEBUG
      filename: logconfig.log
    console:
      class: logging.StreamHandler
      formatter: standard
      level: DEBUG
  loggers:
    aea:
      handlers:
      - logfile
      - console
      level: DEBUG
      propagate: False
```
``` yaml
logging_config:
  version: 1
  disable_existing_loggers: false
  formatters:
    standard:
      format: '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
  handlers:
    http:
      class: logging.handlers.HTTPHandler
      formatter: standard
      level: INFO
      host: localhost:5000
      url: /stream
      method: POST
  loggers:
    aea:
      handlers:
      - http
      level: INFO
      propagate: false
```
