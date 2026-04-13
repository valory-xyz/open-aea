# `aealite`

`aealite` is a lightweight implementation of an AEA library in Golang.


## Usage example

``` golang
package main

import (
	"log"
	"os"
	"os/signal"

	aea "aealite"
	connections "aealite/connections"
)

func main() {

	var err error

	// env file
	if len(os.Args) != 2 {
		log.Print("Usage: main ENV_FILE")
		os.Exit(1)
	}
	envFile := os.Args[1]

	log.Print("Agent starting ...")


	// Create agent
	agent := aea.Agent{}

	// Set connection
	agent.Connection = &connections.P2PClientApi{}

	// Initialise agent from environment file (first arg to process)
	err = agent.InitFromEnv(envFile)
	if err != nil {
		log.Fatal("Failed to initialise agent", err)
	}
	log.Print("successfully initialized AEA!")

	err = agent.Start()
	if err != nil {
		log.Fatal("Failed to start agent", err)
	}
	log.Print("successfully started AEA!")

	// // Send envelope to target
	// agent.Put(envel)
	// // Print out received envelopes
	// go func() {
	// 	for envel := range agent.Queue() {
	// 		envelope := envel
	// 		logger.Info().Msgf("received envelope: %s", envelope)
	// 	}
	// }()

	// Wait until Ctrl+C or a termination call is done.
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

	err = agent.Stop()
	if err != nil {
		log.Fatal("Failed to stop agent", err)
	}
	log.Print("Agent stopped")
}
```

## Development

To run all tests run:

``` bash
go test -p 1 -timeout 0 -count 1 -v ./...
```

To lint:

``` bash
golines . -w
golangci-lint run
```

To generate protoc files:

``` bash
cd ..
protoc -I="aealite/protocols/" --go_out="." aealite/protocols/acn.proto
protoc -I="aealite/protocols/" --go_out="." aealite/protocols/base.proto
cd aealite
```

## Tests

Unit tests are run by default and do not require any external service:

``` bash
go test ./...
```

The tests in `agent_test.go` and `connections/p2pclient_test.go` are
integration tests that talk to a running AEA `p2p_libp2p_client` peer. They
are gated behind the `integration` build tag and are therefore excluded from
the default `go test` run. To execute them, first start an AEA with a
`p2p_libp2p_client` connection configured to match the values in
`test_env_file.env` (ledger `fetchai`, matching keys, and a reachable ACN
delegate at `acn.fetch.ai:11000` or your local peer), then run:

``` bash
go test -tags integration ./...
```
