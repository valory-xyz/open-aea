# Solana crypto plug-in

Solana crypto plug-in for the AEA framework.

## Install

```
pip install open-aea[all]
python setup.py install

```

## Run tests

```bash
pytest
```



## Start

```bash
python3.10 -m venv .venv && source .venv/bin/activate
```

## Pull and start testnet docker image

```bash
docker pull dassy23/solana-test-ledger:latest
```

```bash
docker run -d -p 8899:8899 -p 8900:8900 dassy23/solana-test-ledger:latest
```

