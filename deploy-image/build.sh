#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeigivc5ht4tg44x22m2vxosooj43vgyy6clcbplbsynvbj2rxwihl4 --remote
cd my_first_aea/
aea install
aea build
