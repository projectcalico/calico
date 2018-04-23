ENVOY_API = vendor/github.com/envoyproxy/data-plane-api
EXT_AUTH = $(ENVOY_API)/envoy/service/auth/v2/
ADDRESS = $(ENVOY_API)/envoy/api/v2/core/address
PROTOC_IMPORTS =  -I $(ENVOY_API) \
                  -I vendor/github.com/gogo/protobuf/protobuf \
                  -I vendor/github.com/gogo/protobuf \
                  -I vendor/github.com/lyft/protoc-gen-validate\
                  -I vendor/github.com/googleapis/googleapis\
                  -I proto\
                  -I ./
PROTOC_MAPPINGS = Mgoogle/protobuf/struct.proto=github.com/golang/protobuf/ptypes/struct,Mgoogle/protobuf/timestamp.proto=github.com/golang/protobuf/ptypes/timestamp,Menvoy/api/v2/core/address.proto=github.com/envoyproxy/data-plane-api/envoy/api/v2/core,Mgoogle/protobuf/wrappers.proto=github.com/golang/protobuf/ptypes/wrappers,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto

proto: $(EXT_AUTH)external_auth.pb.go $(ADDRESS).pb.go $(EXT_AUTH)attribute_context.pb.go proto/felixbackend.pb.go

$(EXT_AUTH)external_auth.pb.go $(EXT_AUTH)attribute_context.pb.go: $(EXT_AUTH)external_auth.proto $(EXT_AUTH)attribute_context.proto
	protoc $(PROTOC_IMPORTS) $(EXT_AUTH)*.proto --go_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(ADDRESS).pb.go: $(ADDRESS).proto
	protoc $(PROTOC_IMPORTS) $(ADDRESS).proto --go_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(EXT_AUTH).proto $(ADDRESS).proto $(ATTRIBUTE_CONTEXT).proto:
	glide install

proto/felixbackend.pb.go: proto/felixbackend.proto
	protoc $(PROTOC_IMPORTS) proto/*.proto --go_out=plugins=grpc,$(PROTOC_MAPPINGS):proto

.PHONY: build
build: proto
	CGO_ENABLED=0 GOOS=linux go build -o docker/dikastes

.PHONY: test
test:
	go test -v ./...
