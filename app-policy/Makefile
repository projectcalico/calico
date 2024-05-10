include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/app-policy

###############################################################################

GENERATED_FILES=proto/felixbackend.pb.go proto/healthz.pb.go
SRC_FILES=$(shell find . -name '*.go' |grep -v vendor) $(GENERATED_FILES)

# Name of the images.
# e.g., <registry>/<name>:<tag>
DIKASTES_IMAGE ?=dikastes
BUILD_IMAGES ?= $(DIKASTES_IMAGE)

LDFLAGS = -X $(PACKAGE_NAME)/buildinfo.GitVersion=$(GIT_DESCRIPTION) \
			-X $(PACKAGE_NAME)/buildinfo.BuildDate=$(DATE) \
			-X $(PACKAGE_NAME)/buildinfo.GitRevision=$(GIT_COMMIT) \
			-B 0x$(BUILD_ID)

##############################################################################
# Download and include ../lib.Makefile before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
include ../lib.Makefile

CONTAINER_CREATED=.image.created-$(ARCH)
CONTAINER_FIPS_CREATED=.image.created-$(ARCH)-fips

FIPS ?= false

ifeq ($(FIPS),true)
CONTAINER_MARKER=$(CONTAINER_FIPS_CREATED)
VALIDARCHES=amd64
BINDIR=bin/$(ARCH)-fips
else
CONTAINER_MARKER=$(CONTAINER_CREATED)
BINDIR=bin
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
	rm -rf bin report
	-docker image rm -f $$(docker images $(DIKASTES_IMAGE) -a -q)

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
$(VALIDARCHES):
	$(MAKE) build ARCH=$@

build-all: $(VALIDARCHES)

.PHONY: build
## Build the binary for the current architecture and platform
build: 
	$(MAKE) $(BINDIR)/dikastes-$(ARCH) ARCH=$(ARCH)
	$(MAKE) $(BINDIR)/healthz-$(ARCH) ARCH=$(ARCH)

$(BINDIR)/dikastes-amd64: ARCH=amd64
$(BINDIR)/dikastes-arm64: ARCH=arm64
$(BINDIR)/dikastes-ppc64le: ARCH=ppc64le
$(BINDIR)/dikastes-s390x: ARCH=s390x
$(BINDIR)/dikastes-%: protobuf $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/dikastes, $@)
else
	$(call build_binary, ./cmd/dikastes, $@)
endif

$(BINDIR)/healthz-amd64: ARCH=amd64
$(BINDIR)/healthz-arm64: ARCH=arm64
$(BINDIR)/healthz-ppc64le: ARCH=ppc64le
$(BINDIR)/healthz-s390x: ARCH=s390x
$(BINDIR)/healthz-%: protobuf $(SRC_FILES)
ifeq ($(FIPS),true)
	$(call build_cgo_boring_binary, ./cmd/healthz, $@)
else
	$(call build_binary, ./cmd/healthz, $@)
endif

# We use gogofast for protobuf compilation.  Regular gogo is incompatible with
# gRPC, since gRPC uses golang/protobuf for marshalling/unmarshalling in that
# case.  See https://github.com/gogo/protobuf/issues/386 for more details.
# Note that we cannot seem to use gogofaster because of incompatibility with
# Envoy's validation library.
# When importing, we must use gogo versions of google/protobuf and
# google/rpc (aka googleapis).
PROTOC_IMPORTS =  -I proto\
		  -I ./

protobuf: proto/felixbackend.pb.go proto/healthz.pb.go

proto/felixbackend.pb.go: proto/felixbackend.proto
	$(DOCKER_RUN) -v $(CURDIR):/src:rw --user $(LOCAL_USER_ID):$(LOCAL_GROUP_ID) \
		      $(PROTOC_CONTAINER) \
		      $(PROTOC_IMPORTS) \
		      proto/*.proto \
		      --gogofast_out=plugins=grpc:proto
	$(MAKE) fix

proto/healthz.pb.go: proto/healthz.proto
	$(DOCKER_RUN) -v $(CURDIR):/src:rw --user $(LOCAL_USER_ID):$(LOCAL_GROUP_ID) \
		      $(PROTOC_CONTAINER) \
		      $(PROTOC_IMPORTS) \
		      proto/*.proto \
		      --gogofast_out=plugins=grpc:proto
	$(MAKE) fix


# Building the image
###############################################################################
.PHONY: image $(DIKASTES_IMAGE)
image: $(DIKASTES_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

$(DIKASTES_IMAGE): $(CONTAINER_MARKER)
$(CONTAINER_CREATED): register Dockerfile $(BINDIR)/dikastes-$(ARCH) $(BINDIR)/healthz-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(CONTAINER_FIPS_CREATED): register Dockerfile $(BINDIR)/dikastes-$(ARCH) $(BINDIR)/healthz-$(ARCH)
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
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
	$(MAKE) FIPS=true retag-build-images-with-registries IMAGETAG=$(VERSION)-fips RELEASE=true LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true retag-build-images-with-registries IMAGETAG=latest-fips RELEASE=true LATEST_IMAGE_TAG=latest-fips
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
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
