#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeiaf6fgfmljz6pl7q6zfs3lhqmqbzydlqcen3qek5jjly77vhjowra --remote
cd my_first_aea/
aea install
aea build
