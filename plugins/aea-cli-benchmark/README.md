# AEA CLI Benchmark Plug-in

CLI extension for benchmarking the AEA framework. Adds an `aea benchmark` command group that runs performance benchmark cases covering agent construction, message throughput, memory usage, decision maker, ACN, and related scenarios.

## Installation and usage

Make sure you have `aea` installed.

Then, install the plug-in:
```bash
pip install open-aea-cli-benchmark
```

Now you should be able to run `aea benchmark`:

```bash
Usage: aea benchmark [OPTIONS] COMMAND [ARGS]...

  Run one of performance benchmark.

Options:
  --help  Show this message and exit.

Commands:
  acn-communication             ACN end-to-end message throughput
  acn-startup                   ACN node startup time
  agent-construction-time       Time to construct an AEA instance
  decision-maker                Decision maker throughput
  dialogues-memory-usage        Memory footprint of dialogue state
  mem-usage                     Agent memory usage under load
  messages-memory-usage         Memory footprint of messages
  multiagent                    Multi-agent throughput
  multiagent-http-dialogues     Multi-agent HTTP dialogue throughput
  proactive                     Proactive skill behaviour benchmark
  reactive                      Reactive skill handler benchmark
  tx-generate                   Transaction generation throughput
```

Run any command with `--help` for per-case options.
