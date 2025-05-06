
The easiest way to run an AEA is using your development environment.

If you would like to run an AEA from a browser you can use <a href="https://colab.research.google.com" target="_blank">Google Colab</a>. <a href="https://gist.github.com/DavidMinarsch/2eeb1541508a61e828b497ab161e1834" target="_blank">This gist</a> can be opened in <a href="https://colab.research.google.com" target="_blank">Colab</a> and implements the <a href="../quickstart">quick start</a>.

For deployment, we recommend you use <a href="https://www.docker.com/" target="_blank">Docker</a>.

## Deployment using a Docker Image

First, we fetch a directory containing a Dockerfile and some dependencies:
``` bash
svn export https://github.com/valory-xyz/open-aea/branches/main/deploy-image
cd deploy-image
```

Then follow the `README.md` contained in the folder.

## Deployment using Kubernetes

For an example of how to use <a href="https://kubernetes.io" target="_blank">Kubernetes</a> navigate to our <a href="https://github.com/valory-xyz/open-aea/tree/main/examples/tac_deploy" target="_blank">TAC deployment example</a>.

## Deployment using a binary

For making an executable binary of your `aea` agent:

1. Create a python file which imports the necessary `aea` modules, and executes the CLI `aea` entrypoint. For example `aea_entrypoint.py`:
```python
"""Script for building the AEA responsible for running an agent."""
import os
import sys
from pathlib import Path
import aea.configurations.validation as validation_module

# patch for the _CUR_DIR value
# we need this because pyinstaller generated binaries handle paths differently
validation_module._CUR_DIR = Path(sys._MEIPASS) / validation_module._CUR_DIR
validation_module._SCHEMAS_DIR = os.path.join(validation_module._CUR_DIR, "schemas")

from aea.cli.core import cli
from google.protobuf.descriptor_pb2 import FileDescriptorProto
from aea.mail.base_pb2 import DESCRIPTOR
from multiaddr.codecs.idna import to_bytes as _
from multiaddr.codecs.uint16be import to_bytes as _
from aea_ledger_ethereum.ethereum import *
from aea_ledger_cosmos.cosmos import *
from aea.crypto.registries.base import *

if __name__ == "__main__":
    cli(prog_name="aea")  # pragma: no cover
```

2. Ensure you have all the dependencies installed in your virtual environment, including `pyinstaller`.

3. Use `pyinstaller` to generate the binary. For example:
```bash
pyinstaller --collect-all gql --collect-all hypothesis --collect-all pycoingecko --collect-all scipy --hidden-import numpy --collect-all pandas --collect-all pyfolio --collect-all twitter_text --collect-all google.generativeai --collect-all peewee --collect-data eth_account --collect-all autonomy --collect-all operate --collect-all aea_ledger_ethereum --collect-all aea_ledger_cosmos --collect-all aea_ledger_ethereum_flashbots --hidden-import aea_ledger_ethereum --hidden-import aea_ledger_cosmos --hidden-import aea_ledger_ethereum_flashbots --hidden-import grpc --hidden-import openapi_core --collect-all google.protobuf --collect-all openapi_core --collect-all openapi_spec_validator --collect-all asn1crypto --hidden-import py_ecc --hidden-import pytz --collect-all twikit --collect-all twitter_text_parser --collect-all textblob --collect-all backports.tarfile --collect-all js2py --onefile aea_entrypoint.py --name aea_bin --collect-all aea
```

Refer to <a href="https://pyinstaller.org/en/stable/usage.html" target="_blank">pyinstaller docs</a> for more details, or check the <a href="https://github.com/valory-xyz/olas-operate-app/blob/v0.2.0-rc137/Makefile#L24-L27" target="_blank">Pearl's example</a>.
