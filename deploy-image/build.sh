#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeid76dcmtfg4wixmecwrzrrbkm5zovjqgxussqehrkufd3kklpvcby --remote
cd my_first_aea/
aea install
aea build
