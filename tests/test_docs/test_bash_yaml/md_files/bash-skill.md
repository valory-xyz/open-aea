``` yaml
name: echo
author: fetchai
version: 0.19.0
type: skill
license: Apache-2.0
aea_version: '>=2.0.0, <3.0.0'
behaviours:
  echo:
    class_name: EchoBehaviour
    args:
      tick_interval: 1.0
handlers:
  echo:
    class_name: EchoHandler
    args:
      foo: bar
models: {}
dependencies: {}
protocols:
- fetchai/default:1.0.0
```
``` bash
aea scaffold error-handler
```
