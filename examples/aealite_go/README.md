# A simple example using the Golang `aealite` module

This folder ships the protobuf definition (`default/default.proto`) and the generated Go code (`default/default.pb.go`) for the `fetchai/default:1.0.0` protocol. An [`aealite`](../../libs/go/aealite/) agent uses these to encode and decode messages on the wire.

A complete, runnable agent built on top of `aealite` lives at [`libs/go/aealite_agent_example/`](../../libs/go/aealite_agent_example/). It initializes itself from an env file, connects to the ACN via a running `valory/p2p_libp2p` or `valory/p2p_libp2p_client` peer, and exchanges `default` protocol messages.

To build and run:

```bash
cd libs/go/aealite_agent_example
go build ./...
./aealite_agent_example --env-file example_env_file.env
```

For an end-to-end check that a Go `aealite` seller can dialogue with a Python AEA buyer over a live libp2p ACN network, see the Python↔Go harness at [`libs/go/aea_end2end/test_fipa_end2end.py`](../../libs/go/aea_end2end/test_fipa_end2end.py).
