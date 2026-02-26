#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeic4n24fjsolgw5yuo4juixau4yxyrm57wg7zp7exqy4enidmnlzp4 --remote
cd my_first_aea/
aea install
aea build
