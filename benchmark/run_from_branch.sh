#!/bin/bash
# Run the open-aea benchmark suite against a fresh clone of this repo at a
# given branch. Produces a plain-text performance report on stdout.
#
# Usage: ./run_from_branch.sh [branch]
#
# The benchmark cases are invoked via the `aea benchmark` CLI provided by
# the `open-aea-cli-benchmark` plugin (see plugins/aea-cli-benchmark/).

set -euo pipefail

REPO=https://github.com/valory-xyz/open-aea.git
BRANCH="${1:-main}"
TMP_DIR=$(mktemp -d -t bench-XXXXXXXXXX)

trap 'rm -rf "$TMP_DIR"' EXIT

git clone --depth 1 --branch "$BRANCH" "$REPO" "$TMP_DIR"
cd "$TMP_DIR"

echo "Creating virtual environment..."
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "Installing open-aea, plugins, and the benchmark CLI..."
pip install --upgrade pip
pip install .[all]
pip install ./plugins/aea-cli-benchmark
pip install --no-deps \
    ./plugins/aea-ledger-fetchai \
    ./plugins/aea-ledger-cosmos \
    ./plugins/aea-ledger-ethereum

DURATION=10
NUM_RUNS=100
MESSAGES=100

echo
echo "Performance report for $(LC_ALL=C date +'%d.%m.%Y_%H:%M')"
echo "-----------------------------"

for mode in threaded async; do
    echo
    echo "Reactive [$mode]: runs=$NUM_RUNS duration=${DURATION}s"
    aea benchmark reactive \
        --duration="$DURATION" \
        --number_of_runs="$NUM_RUNS" \
        --runtime_mode="$mode"
done

for mode in threaded async; do
    echo
    echo "Proactive [$mode]: runs=$NUM_RUNS duration=${DURATION}s"
    aea benchmark proactive \
        --duration="$DURATION" \
        --number_of_runs="$NUM_RUNS" \
        --runtime_mode="$mode"
done

for mode in threaded async; do
    for agents in 2 4 8 16 32 64 128; do
        echo
        echo "MultiAgent [$mode, n=$agents]: runs=$NUM_RUNS duration=${DURATION}s messages=$MESSAGES"
        aea benchmark multiagent_message_exchange \
            --num_of_agents="$agents" \
            --duration="$DURATION" \
            --number_of_runs="$NUM_RUNS" \
            --runtime_mode="$mode" \
            --runner_mode=threaded \
            --start_messages="$MESSAGES"
    done
done

echo
echo "Done!"
