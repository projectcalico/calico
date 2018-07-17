# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=$(patsubst docker-image/Dockerfile.%,%,$(wildcard docker-image/Dockerfile.*))


# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)

# canonicalized names for host architecture
ifeq ($(BUILDARCH),aarch64)
        BUILDARCH=arm64
endif
ifeq ($(BUILDARCH),x86_64)
        BUILDARCH=amd64
endif

# unless otherwise set, I am building for my own architecture, i.e. not cross-compiling
ARCH ?= $(BUILDARCH)

# canonicalized names for target architecture
ifeq ($(ARCH),aarch64)
        override ARCH=arm64
endif
ifeq ($(ARCH),x86_64)
    override ARCH=amd64
endif

PROTOC_VER ?= v0.1
PROTOC_CONTAINER ?= calico/protoc:$(PROTOC_VER)-$(BUILDARCH)

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
MY_UID:=$(shell id -u)
MY_GID:=$(shell id -g)

# Pre-configured docker run command that runs as this user with the repo
# checked out to /code, uses the --rm flag to avoid leaving the container
# around afterwards.
DOCKER_RUN_RM:=docker run --rm --user $(MY_UID):$(MY_GID) -v $${PWD}:/code

ENVOY_API = vendor/github.com/envoyproxy/data-plane-api
EXT_AUTH = $(ENVOY_API)/envoy/service/auth/v2alpha/
ADDRESS = $(ENVOY_API)/envoy/api/v2/core/address
V2_BASE = $(ENVOY_API)/envoy/api/v2/core/base
HTTP_STATUS = $(ENVOY_API)/envoy/type/http_status

# We use gogofast for protobuf compilation.  Regular gogo is incompatible with
# gRPC, since gRPC uses golang/protobuf for marshalling/unmarshalling in that
# case.  See https://github.com/gogo/protobuf/issues/386 for more details.
# Note that we cannot seem to use gogofaster because of incompatibility with
# Envoy's validation library.
# When importing, we must use gogo versions of google/protobuf and
# google/rpc (aka googleapis).
PROTOC_IMPORTS =  -I $(ENVOY_API) \
                  -I vendor/github.com/gogo/protobuf/protobuf \
                  -I vendor/github.com/gogo/protobuf \
                  -I vendor/github.com/lyft/protoc-gen-validate\
                  -I vendor/github.com/gogo/googleapis\
                  -I proto\
                  -I ./
# Also remap the output modules to gogo versions of google/protobuf and google/rpc
PROTOC_MAPPINGS = Menvoy/api/v2/core/address.proto=github.com/envoyproxy/data-plane-api/envoy/api/v2/core,Menvoy/api/v2/core/base.proto=github.com/envoyproxy/data-plane-api/envoy/api/v2/core,Menvoy/type/http_status.proto=github.com/envoyproxy/data-plane-api/envoy/type,Mgogoproto/gogo.proto=github.com/gogo/protobuf/gogoproto,Mgoogle/protobuf/any.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/duration.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/struct.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/timestamp.proto=github.com/gogo/protobuf/types,Mgoogle/protobuf/wrappers.proto=github.com/gogo/protobuf/types,Mgoogle/rpc/status.proto=github.com/gogo/googleapis/google/rpc

proto: $(EXT_AUTH)external_auth.pb.go $(ADDRESS).pb.go $(V2_BASE).pb.go $(HTTP_STATUS).pb.go $(EXT_AUTH)attribute_context.pb.go proto/felixbackend.pb.go

$(EXT_AUTH)external_auth.pb.go $(EXT_AUTH)attribute_context.pb.go: $(EXT_AUTH)external_auth.proto $(EXT_AUTH)attribute_context.proto
	$(DOCKER_RUN_RM) -v $${PWD}:/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              $(EXT_AUTH)*.proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(ADDRESS).pb.go $(V2_BASE).pb.go: $(ADDRESS).proto $(V2_BASE).proto
	$(DOCKER_RUN_RM) -v $${PWD}:/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              $(ADDRESS).proto $(V2_BASE).proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(HTTP_STATUS).pb.go: $(HTTP_STATUS).proto
	$(DOCKER_RUN_RM) -v $${PWD}:/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              $(HTTP_STATUS).proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(EXT_AUTH)external_auth.proto $(ADDRESS).proto $(V2_BASE).proto $(HTTP_STATUS).proto $(EXT_AUTH)attribute_context.proto:
	glide install -v

proto/felixbackend.pb.go: proto/felixbackend.proto
	$(DOCKER_RUN_RM) -v $${PWD}:/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              proto/*.proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):proto

.PHONY: build
build: proto
	CGO_ENABLED=0 GOOS=linux go build -o docker/dikastes

.PHONY: test
test: proto
	go test -v ./...

.PHONY: clean
clean:
	rm -rf vendor
