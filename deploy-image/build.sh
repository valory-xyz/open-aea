#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeif5ni3ynryj4x2bzs5zdevph36sra7wryepblzi6yenr6gxxsafw4 --remote
cd my_first_aea/
aea install
aea build
