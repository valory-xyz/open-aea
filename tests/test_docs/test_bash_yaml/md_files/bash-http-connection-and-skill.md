``` bash
aea create my_aea
cd my_aea
```
``` bash
aea add connection valory/http_server:0.22.0:bafybeic3jpkum7g6qo6x6vdrmvvhj7vqw7ec2op72uc3yfhmnlp5hn3joy --remote
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
aea add connection valory/http_server:0.22.0:bafybeic3jpkum7g6qo6x6vdrmvvhj7vqw7ec2op72uc3yfhmnlp5hn3joy --remote
aea push connection valory/http_server --local
aea add protocol fetchai/default:1.0.0:bafybeiaf3qhrdttthrisrl2tlpt3mpo5btkozw2dnxlj4cbqq56ilcl6oa --remote
aea push protocol fetchai/default --local
aea add protocol valory/http:1.0.0:bafybeih4azmfwtamdbkhztkm4xitep3gx6tfdnoz6tvllmaqnhu3klejfa --remote
aea push protocol valory/http --local
cd ..
aea delete my_aea
```