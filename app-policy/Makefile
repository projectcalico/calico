include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/app-policy

###############################################################################

GENERATED_FILES=../felix/proto/felixbackend.pb.go proto/healthz.pb.go
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


###############################################################################
# Protobufs,
#
# 1. defer to felix's makefile for felixbackend stuff
# 2. build proto for healthz
###############################################################################

../felix/proto/felixbackend.pb.go: ../felix/proto/felixbackend.proto
	$(MAKE) --directory ../felix protobuf

protobuf: $(GENERATED_FILES)

proto/healthz.pb.go: proto/healthz.proto
	$(DOCKER_RUN) -v $(CURDIR)/proto:/proto:rw \
		$(CALICO_BUILD) \
			sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=. --go_opt=paths=source_relative healthz.proto'
	$(MAKE) fix-changed


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
$(CONTAINER_CREATED): register Dockerfile $(BINDIR)/dikastes-$(ARCH) $(BINDIR)/healthz-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

$(CONTAINER_FIPS_CREATED): register Dockerfile $(BINDIR)/dikastes-$(ARCH) $(BINDIR)/healthz-$(ARCH) bin/LICENSE
	$(DOCKER_BUILD) --build-arg BIN_DIR=$(BINDIR) -t $(DIKASTES_IMAGE):latest-fips-$(ARCH) -f Dockerfile .
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

bin/LICENSE: ../LICENSE.md
	cp ../LICENSE.md $@
###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: protobuf
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "cd /go/src/$(PACKAGE_NAME) && go test -v ./..."

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
