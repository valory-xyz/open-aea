#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeieckawitsabcav6cb4eqvmhbhnpvwbfroyp4icuf6s6mhuraue22q --remote
cd my_first_aea/
aea install
aea build
