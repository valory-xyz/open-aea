# Benchmarks

This directory contains two related things:

1. The **`aea benchmark` suite runner** (`run_from_branch.sh` +
   `Dockerfile` + `benchmark-deployment.yaml`) that clones a branch of
   `open-aea`, installs it, and runs a fixed battery of benchmarks via
   the `open-aea-cli-benchmark` plugin.
2. A small in-house **`BenchmarkControl`** framework (`framework/`)
   used by the `cases/cpu_burn.py` teaching example and documented in
   `docs/performance-benchmark.md`.

The per-case benchmark logic itself (reactive, proactive,
multiagent, mem usage, decision maker, etc.) lives in
`plugins/aea-cli-benchmark/` and is invoked as `aea benchmark <case>`.

## Running the benchmark suite locally

From a fresh checkout of this repo, against the current branch:

``` bash
./benchmark/run_from_branch.sh $(git rev-parse --abbrev-ref HEAD)
```

Or to pin a specific branch and save to file:

``` bash
./benchmark/run_from_branch.sh main | tee benchmark.txt
```

The script clones the branch into a temp dir, creates a fresh
virtualenv, installs `open-aea[all]` + the benchmark plugin + the
three ledger plugins, and then invokes `aea benchmark reactive`,
`aea benchmark proactive`, and `aea benchmark multiagent_message_exchange`
with a parameter sweep.

## Running individual cases

Any single case can be run directly:

``` bash
aea benchmark reactive --duration 10 --number_of_runs 100 --runtime_mode async
aea benchmark proactive --duration 10 --number_of_runs 100 --runtime_mode async
aea benchmark multiagent_message_exchange --num_of_agents 16 --duration 10 --number_of_runs 100
```

See `aea benchmark --help` for the full list.

## Deploying a benchmark run and serving results (k8s)

Build and push the image from `benchmark/Dockerfile`, then:

``` bash
kubectl delete configmap run-benchmark 2>/dev/null || true
kubectl create configmap run-benchmark --from-file=run_from_branch.sh
kubectl apply -f benchmark-deployment.yaml
```

To remove old pods (auto-restarts new pod):

``` bash
kubectl delete pod NODE_NAME
```

To completely remove:

``` bash
kubectl delete deployment benchmark
```

List pods:

``` bash
kubectl get pod -o wide
```

Access the results via NGINX:

``` bash
kubectl port-forward NODE_NAME 8000:80
curl localhost:8000 | tee results.txt
```
