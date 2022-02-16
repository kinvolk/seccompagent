.PHONY: generated-files
generated-files: seccomp-agent.pb.go

seccomp-agent.pb.go: seccomp-agent.proto
	protoc --go_out=. --go_opt=paths=source_relative --go-grpc_out=. --go-grpc_opt=paths=source_relative seccomp-agent.proto

clean:
	rm -f seccomp-agent.pb.go seccomp-agent_grpc.pb.go
