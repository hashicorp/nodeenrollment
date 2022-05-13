proto:
	protoc types/github.com.hashicorp.nodeenrollment.types.v1.proto --go_out=paths=source_relative:.

.PHONY: proto
