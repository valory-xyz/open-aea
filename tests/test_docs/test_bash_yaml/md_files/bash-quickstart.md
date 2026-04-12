``` bash
python3 --version
```
``` bash
sudo apt-get install python3.10-dev
```
``` bash
curl https://raw.githubusercontent.com/valory-xyz/open-aea/main/scripts/install.sh --output install.sh
chmod +x install.sh
./install.sh
```
``` bash
docker pull valory/open-aea-user:latest
```
``` bash
docker run -it -v $(pwd):/agents --workdir=/agents valory/open-aea-user:latest
```
``` bash
docker run -it -v %cd%:/agents --workdir=/agents valory/open-aea-user:latest
```
``` bash
mkdir my_aea_projects/ && cd my_aea_projects/
```
``` bash
python3.10 -m venv .venv && source .venv/bin/activate
```
``` bash
echo "$SHELL"
```
``` bash
pip install open-aea[all]
pip install open-aea-cli-ipfs
```
``` bash
aea init --remote
```
``` bash
aea fetch open_aea/my_first_aea:0.1.0:bafybeid76dcmtfg4wixmecwrzrrbkm5zovjqgxussqehrkufd3kklpvcby --remote
cd my_first_aea
```
``` bash
aea install
```
``` bash
aea generate-key ethereum
aea add-key ethereum
```
``` bash
aea run
```
``` bash
    _     _____     _
   / \   | ____|   / \
  / _ \  |  _|    / _ \
 / ___ \ | |___  / ___ \
/_/   \_\|_____|/_/   \_\

v2.1.0

Starting AEA 'my_first_aea' in 'async' mode ...
info: Echo Handler: setup method called.
info: Echo Behaviour: setup method called.
info: [my_first_aea]: Start processing messages...
info: Echo Behaviour: act method called.
info: Echo Behaviour: act method called.
info: Echo Behaviour: act method called.
...
```
``` bash
echo 'my_first_aea,sender_aea,fetchai/default:1.0.0,\x12\x10\x08\x01\x12\x011*\t*\x07\n\x05hello,' >> input_file
```
``` bash
info: Echo Behaviour: act method called.
Echo Handler: message=Message(sender=sender_aea,to=my_first_aea,content=b'hello',dialogue_reference=('1', ''),message_id=1,performative=bytes,target=0), sender=sender_aea
info: Echo Behaviour: act method called.
info: Echo Behaviour: act method called.
```
``` bash
info: Echo Behaviour: act method called.
info: Echo Behaviour: act method called.
^C my_first_aea interrupted!
my_first_aea stopping ...
info: Echo Handler: teardown method called.
info: Echo Behaviour: teardown method called.
```
``` bash
aea create my_first_aea
cd my_first_aea
```
``` bash
aea add connection fetchai/stub:0.21.0:bafybeihjlr7xeurjm56ckji3gjjlao4pykkgk5xcdmfpjraxwyaljmlh4q --remote
```
``` bash
aea add skill fetchai/echo:0.19.0:bafybeieqhk2g6l4pitjmuwbtt7n6vx3wawclygjv5cywjjrgay66lzq74u --remote
```
``` bash
TO,SENDER,PROTOCOL_ID,ENCODED_MESSAGE,
```
``` bash
recipient_aea,sender_aea,fetchai/default:1.0.0,\x08\x01\x12\x011*\x07\n\x05hello,
```
``` bash
mkdir packages
cd my_first_aea
aea add protocol fetchai/default:1.0.0:bafybeih4zgjm7ifmovpzuwdobwb2kotvvr4gx3suwbn5j5z3pau4sioaou --remote
aea push protocol fetchai/default --local
cd ..
aea delete my_aea
```
``` bash
pytest test.py
```
``` bash
aea delete my_first_aea
```
