#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeiakpjbpsqbmgqdg6c36nhujqmk446u2qn7jvi2lefmnyxtmnv3tqe --remote
cd my_first_aea/
aea install
aea build
