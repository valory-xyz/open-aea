#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeibv7nlyxldyj5ntivsu74ylul4dltpfvkfa46k2pbveetfpkvz4jm --remote
cd my_first_aea/
aea install
aea build
