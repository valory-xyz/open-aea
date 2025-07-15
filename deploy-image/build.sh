#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeicw7hmrjnqzqeyl2rbymdzklon6f74rh35lxjsilbze7ff4of7lja --remote
cd my_first_aea/
aea install
aea build
