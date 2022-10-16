#!/bin/bash
set -e

# setup the agent
aea fetch open_aea/my_first_aea:0.1.0:bafybeiatpcydp3ieneweisyxr35arg5hazcrxhdrlhatqpsmxmqivnuv7q --remote
cd my_first_aea/
aea install
aea build
