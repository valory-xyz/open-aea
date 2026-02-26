``` bash
aea fetch open_aea/gym_aea:0.1.0:bafybeibg646e7xffozfiwd4h3ikkdnlmy3a2rwzuv4tajqdefqzn3eaodi --remote
cd gym_aea
aea install
```
``` bash
aea create my_gym_aea
cd my_gym_aea
```
``` bash
aea add skill fetchai/gym:0.20.0:bafybeifx3kvfpq7ad2gkcsjkxzdpxopehz3cmnsxnf4og6mrzom6m7nlp4 --remote
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
