include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/app-policy

###############################################################################

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
LOCAL_USER_ID:=$(shell id -u)
MY_GID:=$(shell id -g)

GENERATED_FILES=proto/felixbackend.pb.go proto/healthz.pb.go
SRC_FILES=$(shell find . -name '*.go' |grep -v vendor) $(GENERATED_FILES)

# Name of the images.
# e.g., <registry>/<name>:<tag>
DIKASTES_IMAGE ?=dikastes
BUILD_IMAGES ?= $(DIKASTES_IMAGE)

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf .go-pkg-cache report vendor bin
	-docker rmi $(DIKASTES_IMAGE):latest-$(ARCH)
	-docker rmi $(DIKASTES_IMAGE):$(VERSION)-$(ARCH)
ifeq ($(ARCH),amd64)
	-docker rmi $(DIKASTES_IMAGE):latest
	-docker rmi $(DIKASTES_IMAGE):$(VERSION)
endif

.PHONY: clean-generated
# Delete (checked-in) generated files. Intentionally not part of the main clean target since these files are
# checked in and deleting them makes the repo "dirty" as far as git is concerned.
clean-generated:
	rm -rf $(GENERATED_FILES)

###############################################################################
# Building the binary
###############################################################################

.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/dikastes-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/dikastes-$(ARCH) bin/healthz-$(ARCH)

bin/dikastes-amd64: ARCH=amd64
bin/dikastes-arm64: ARCH=arm64
bin/dikastes-ppc64le: ARCH=ppc64le
bin/dikastes-s390x: ARCH=s390x
bin/dikastes-%: protobuf $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN_RO) \
	  -e CGO_ENABLED=$(CGO_ENABLED) \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  $(CALICO_BUILD) go build $(BUILD_FLAGS) -ldflags "-X main.VERSION=$(GIT_VERSION)" -v -o bin/dikastes-$(ARCH) ./cmd/dikastes

bin/healthz-amd64: ARCH=amd64
bin/healthz-arm64: ARCH=arm64
bin/healthz-ppc64le: ARCH=ppc64le
bin/healthz-s390x: ARCH=s390x
bin/healthz-%: protobuf $(SRC_FILES)
	mkdir -p bin || true
	-mkdir -p .go-pkg-cache $(GOMOD_CACHE) || true
	$(DOCKER_RUN_RO) \
	  -e CGO_ENABLED=$(CGO_ENABLED) \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  $(CALICO_BUILD) go build $(BUILD_FLAGS) -ldflags "-X main.VERSION=$(GIT_VERSION)" -v -o bin/healthz-$(ARCH) ./cmd/healthz

# We use gogofast for protobuf compilation.  Regular gogo is incompatible with
# gRPC, since gRPC uses golang/protobuf for marshalling/unmarshalling in that
# case.  See https://github.com/gogo/protobuf/issues/386 for more details.
# Note that we cannot seem to use gogofaster because of incompatibility with
# Envoy's validation library.
# When importing, we must use gogo versions of google/protobuf and
# google/rpc (aka googleapis).
PROTOC_IMPORTS =  -I proto -I ./

PROTOS := $(wildcard proto/*.proto)
.PHONY: $(PROTOS)
$(PROTOS):
	$(DOCKER_RUN) -v $(CURDIR):/src:rw 					\
	--user $(LOCAL_USER_ID):$(LOCAL_USER_ID) 			\
	$(PROTOC_CONTAINER) 								\
	$(PROTOC_IMPORTS) 									\
	$@ 													\
	--gogofast_out=\
	plugins=grpc:proto

protobuf: $(PROTOS) fix



# Building the image
###############################################################################
CONTAINER_CREATED=.dikastes.created-$(ARCH)
.PHONY: image $(DIKASTES_IMAGE)
image: $(DIKASTES_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(DIKASTES_IMAGE): $(CONTAINER_CREATED)
$(CONTAINER_CREATED): Dockerfile.$(ARCH) bin/dikastes-$(ARCH) bin/healthz-$(ARCH)
	$(DOCKER_BUILD) -t $(DIKASTES_IMAGE):latest-$(ARCH) -f Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: protobuf
	mkdir -p report
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "go test -v $(GINKGO_ARGS) ./... | go-junit-report > ./report/tests.xml"

###############################################################################
# CI
###############################################################################

.PHONY: ci
ci: mod-download build-all check-generated-files static-checks ut

check-boring-ssl: bin/dikastes-amd64
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		go tool nm bin/dikastes-amd64 > bin/tags.txt && grep '_Cfunc__goboringcrypto_' bin/tags.txt 1> /dev/null
	-rm -f bin/tags.txt

## Check if generated files are out of date
.PHONY: check-generated-files
check-generated-files:
	$(MAKE) clean
	$(MAKE) protobuf
	if (git describe --tags --dirty | grep -c dirty >/dev/null); then \
	  echo "Generated files are out of date."; \
	  false; \
	else \
	  echo "Generated files are up to date."; \
	fi

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created 
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(DIKASTES_IMAGE):$(VERSION)-$(ARCH) /dikastes --version | grep '^$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(DIKASTES_IMAGE):$(VERSION)-$(ARCH) /dikastes --version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
