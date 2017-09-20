proto: proto/authz.pb.go

proto/authz.pb.go: proto/authz.proto
	protoc -I proto/ proto/authz.proto --go_out=plugins=grpc:proto