#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeigrqnsuzotjj3gnz4zqutbp52plbr473lvqau5a2uh7mtfeyiujsq --remote
cd my_first_aea/
aea install
aea build
