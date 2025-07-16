``` bash
aea create my_aea
cd my_aea
```
``` bash
aea add connection valory/http_server:0.22.0:bafybeiegcpryvvquu24xlm3kqsaxvwgxij44lky6tp6mv6tpadhgg6guqa --remote
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
aea add connection valory/http_server:0.22.0:bafybeiegcpryvvquu24xlm3kqsaxvwgxij44lky6tp6mv6tpadhgg6guqa --remote
aea push connection valory/http_server --local
aea add protocol fetchai/default:1.0.0:bafybeifs26twgfmrcxxxrexsa42aol3rbktdqa3u5vvjlywzm5rh2nfmee --remote
aea push protocol fetchai/default --local
aea add protocol valory/http:1.0.0:bafybeibxab2yfpchusrzw4rgrasjomtpphazanpivhhtznmuao5ny2lsmi --remote
aea push protocol valory/http --local
cd ..
aea delete my_aea
```