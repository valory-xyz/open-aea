``` bash
aea fetch open_aea/gym_aea:0.1.0:bafybeicbwitdt6zpuhbwet7tarnujwvkm4nrjxshc77bwkn7scpyxgj67e --remote
cd gym_aea
aea install
```
``` bash
aea create my_gym_aea
cd my_gym_aea
```
``` bash
aea add skill fetchai/gym:0.20.0:bafybeih4ark3b5rbuge6js2zdf5sexogeqvbz2vqpg6itvwx7emynxsnme --remote
```
``` bash
aea config set agent.default_connection fetchai/gym:0.19.0
```
``` bash
aea install
```
``` bash
mkdir gyms
cp -a ../examples/gym_ex/gyms/. gyms/
```
``` bash
aea config set vendor.fetchai.connections.gym.config.env 'gyms.env.BanditNArmedRandom'
```
``` bash
aea generate-key ethereum
aea add-key ethereum
```
``` bash
aea run
```
``` bash
cd ..
aea delete my_gym_aea
```
