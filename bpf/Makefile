generate:
	go generate ./...

build: generate
	go build -o ./bin/procexec ./cmd/procexec/
	go build -o ./bin/tcplat ./cmd/tcplat/
	go build -o ./bin/tcpstats ./cmd/tcpstats/