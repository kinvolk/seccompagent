GO_BUILD := go build 

all:
	$(GO_BUILD) -o seccompagent ./cmd/seccompagent

