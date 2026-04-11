``` bash
aea create my_aea
cd my_aea
```
``` bash
aea add connection valory/http_server:0.22.0:bafybeihs6dufyaa5l4uorplzx3wiyna5qlq2x43tmyl3yonkl265vspdle --remote
```
``` bash
aea config set agent.default_connection valory/http_server:0.22.0
```
``` bash
aea config set vendor.fetchai.connections.http_server.config.api_spec_path "../examples/http_ex/petstore.yaml"
```
``` bash
aea generate-key ethereum
aea add-key ethereum
```
``` bash
aea install
```
``` bash
aea scaffold skill http_echo
```
``` bash
aea fingerprint skill fetchai/http_echo:0.20.0
```
``` bash
aea config set vendor.fetchai.connections.http_server.config.target_skill_id "$(aea config get agent.author)/http_echo:0.1.0"
```
``` bash
aea run
```
``` yaml
handlers:
  http_handler:
    args: {}
    class_name: HttpHandler
models:
  default_dialogues:
    args: {}
    class_name: DefaultDialogues
  http_dialogues:
    args: {}
    class_name: HttpDialogues
```

``` bash
mkdir packages
aea create my_aea
cd my_aea
aea add connection valory/http_server:0.22.0:bafybeihs6dufyaa5l4uorplzx3wiyna5qlq2x43tmyl3yonkl265vspdle --remote
aea push connection valory/http_server --local
aea add protocol fetchai/default:1.0.0:bafybeih4zgjm7ifmovpzuwdobwb2kotvvr4gx3suwbn5j5z3pau4sioaou --remote
aea push protocol fetchai/default --local
aea add protocol valory/http:1.0.0:bafybeidxkp3vga7t6x2pbt2tpkgyaxa5bgpdgryao54py7w3yxyzr7neoy --remote
aea push protocol valory/http --local
cd ..
aea delete my_aea
```