
clean:
	rm -f coverage.txt
	rm -f libp2p_node

install:
	go get -v -t -d ./...

build:
	go build

test:
	go test -gcflags=-l -p 1 -timeout 0 -count 1 -covermode=atomic -coverprofile=coverage.txt -v ./...
	go tool cover -func=coverage.txt

lint:
	golines . -w
	golangci-lint run

race_test:
	go test -gcflags=-l -p 1 -timeout 0 -count 1 -race -v ./...
