``` bash
aea fetch open_aea/gym_aea:0.1.0:bafybeidvo5wi7ku6t7664poqpxkvr7cbzvtyew6isc6ro42brjtbxtpdiq --remote
cd gym_aea
aea install
```
``` bash
aea create my_gym_aea
cd my_gym_aea
```
``` bash
aea add skill fetchai/gym:0.20.0:bafybeibbijy6i77zif7slkbqnai476ofhha4rawvgv6rflwg6p77j6c6wm --remote
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
