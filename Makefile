ENVOY_API = vendor/github.com/envoyproxy/data-plane-api
EXT_AUTH = $(ENVOY_API)/api/auth/external_auth
ADDRESS = $(ENVOY_API)/api/address
PROTOC_IMPORTS =  -I $(ENVOY_API) \
                  -I vendor/github.com/gogo/protobuf/protobuf \
                  -I vendor/github.com/gogo/protobuf \
                  -I vendor/github.com/lyft/protoc-gen-validate\
                  -I vendor/github.com/googleapis/googleapis\
                  -I proto\
                  -I ./
PROTOC_MAPPINGS = Mgoogle/protobuf/struct.proto=github.com/golang/protobuf/ptypes/struct,Mgoogle/protobuf/timestamp.proto=github.com/golang/protobuf/ptypes/timestamp,Mapi/address.proto=github.com/envoyproxy/data-plane-api/api,Mgoogle/protobuf/wrappers.proto=github.com/golang/protobuf/ptypes/wrappers,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto

proto: $(EXT_AUTH).pb.go $(ADDRESS).pb.go proto/felixbackend.pb.go

$(EXT_AUTH).pb.go: $(EXT_AUTH).proto
	protoc $(PROTOC_IMPORTS) $(EXT_AUTH).proto --go_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(ADDRESS).pb.go: $(ADDRESS).proto
	protoc $(PROTOC_IMPORTS) $(ADDRESS).proto --go_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(EXT_AUTH).proto $(ADDRESS).proto:
	glide install

proto/felixbackend.pb.go: proto/felixbackend.proto
	protoc $(PROTOC_IMPORTS) proto/*.proto --go_out=plugins=grpc,$(PROTOC_MAPPINGS):proto
