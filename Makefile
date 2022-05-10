proto:
	protoc nodetypes/github.com.hashicorp.nodeenrollment.nodetypes.v1.proto --go_out=paths=source_relative:.
	protoc multihop/github.com.hashicorp.nodeenrollment.multihop.v1.proto --go_out=paths=source_relative:. --go-grpc_out=paths=source_relative:.

.PHONY: proto
