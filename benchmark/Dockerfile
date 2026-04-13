FROM python:3.10-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        bash \
        curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

RUN pip install --no-cache-dir \
        "open-aea[all]" \
        open-aea-cli-benchmark \
        open-aea-ledger-fetchai \
        open-aea-ledger-cosmos \
        open-aea-ledger-ethereum
