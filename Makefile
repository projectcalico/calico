proto: proto/authz.pb.go

proto/authz.pb.go: proto/authz.proto
	protoc -I proto/ proto/authz.proto --go_out=plugins=grpc:proto

.PHONY: dikastes
dikastes:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o dikastes .

.PHONY: image
image: dikastes
	docker build -t cluster-local:5000/tigera/dikastes:latest .