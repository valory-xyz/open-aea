#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeifptjiktbm4cl7hgu74regnj5ltbkbfmfrsstwpexqcru2zadko2u --remote
cd my_first_aea/
aea install
aea build
