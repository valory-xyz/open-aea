#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeifii3674fbefcbpg7vhkiutiuxtim37s2wjjryyj2rgiolrty63vu --remote
cd my_first_aea/
aea install
aea build
