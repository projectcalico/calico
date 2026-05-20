include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/pod2daemon

# The node-driver-registrar binary is the only standalone binary produced by
# pod2daemon. It is cloned from upstream and packaged as the standalone
# calico/node-driver-registrar image via ko (registrar.ko.yaml). The CSI
# driver and flex volume driver are compiled into the main calico binary as
# subcommands.
REGISTRAR_IMAGE ?= node-driver-registrar
BUILD_IMAGES ?= $(REGISTRAR_IMAGE)

###############################################################################
# Download and include ../lib.Makefile before anything else
###############################################################################

include ../lib.Makefile

###############################################################################

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf report/
	rm -rf bin
	-docker image rm -f $$(docker images $(REGISTRAR_IMAGE) -a -q) 2>/dev/null
	$(MAKE) clean-registrar

###############################################################################
# Building the binary
###############################################################################
BINDIR=bin

.PHONY: build
## Build the node-driver-registrar binary for the current architecture.
build: $(BINDIR)/node-driver-registrar-$(ARCH)

protobuf proto/udsver.pb.go: proto/udsver.proto
	$(DOCKER_RUN) -v $(CURDIR)/proto:/proto:rw \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=. --go_opt=paths=source_relative udsver.proto'
	# Make sure the generated code won't cause a static-checks failure.
	$(MAKE) fix-changed

UPSTREAM_REGISTRAR_PROJECT ?= kubernetes-csi/$(REGISTRAR_IMAGE)
UPSTREAM_REGISTRAR_TAG     ?= f0fd46fc3fbdb6fe20fc2d2614631816b551a143 #https://github.com/kubernetes-csi/node-driver-registrar/commit/f0fd46fc3fbdb6fe20fc2d2614631816b551a143

REGISTRAR_TIGERA_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
	go build -tags $(TAGS) -buildvcs=false -v -o $(BINDIR)/csi-node-driver-registrar cmd/csi-node-driver-registrar/*.go"
REGISTRAR_UPSTREAM_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && make build BUILD_PLATFORMS=$(BUILD_PLATFORMS)"

ifeq ($(ARCH), $(filter $(ARCH),amd64))
# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
CGO_ENABLED=1
GOEXPERIMENT=""
else ifeq ($(ARCH), $(filter $(ARCH),arm64))
CGO_ENABLED=0
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),ppc64le))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='linux ppc64le ppc64le'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),s390x))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='linux s390x s390x'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),win64))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='windows amd64 amd64'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
endif

$(BINDIR)/node-driver-registrar-%: clone-registrar-upstream
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) \
			-v $(REPO_ROOT)/pod2daemon/$(REGISTRAR_IMAGE):/go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT):rw \
			$(CALICO_BUILD) \
			/bin/bash -c $(REGISTRAR_BUILD_CMD)
			mv $(REGISTRAR_IMAGE)/$(BINDIR)/csi-node-driver-registrar $@

clone-registrar-upstream:
ifeq ("$(wildcard ./$(REGISTRAR_IMAGE))", "")
	@echo "Directory does not exist."
	git clone --depth 1 --single-branch https://github.com/$(UPSTREAM_REGISTRAR_PROJECT).git
else
	@echo "Upstream repo already cloned."
endif
	cd $(REGISTRAR_IMAGE) && \
	  git checkout $(UPSTREAM_REGISTRAR_TAG) || \
	  git fetch --tags origin $(UPSTREAM_REGISTRAR_TAG) && \
	  git checkout $(UPSTREAM_REGISTRAR_TAG)
	rm -rf ./$(REGISTRAR_IMAGE)/vendor

clean-registrar:
	rm -rf ./$(REGISTRAR_IMAGE)
	rm -f .image.created-*

###############################################################################
# Build the csi-node-driver-registrar OCI image directly with ko.
#
# We build from the upstream clone (it has its own go.mod) to dodge the
# diamond dependency conflicts that show up when adding csi-node-driver-
# registrar to the calico monorepo's go.mod via a `tool` directive. The
# .ko.yaml lives in our source tree (registrar.ko.yaml or registrar.ko.fips.yaml)
# and is copied into the clone at build time so `make clean-registrar`
# doesn't lose it.
###############################################################################
FIPS ?= false
ifeq ($(FIPS),true)
CONTAINER_MARKER = .image.created-$(ARCH)-fips
IMAGE_TAG = latest-fips
VALIDARCHES = amd64
KO_CONFIG = registrar.ko.fips.yaml
# FIPS needs CGO + GOEXPERIMENT=boringcrypto. Run ko inside calico/go-build
# for a known-good cross/CGO toolchain; mount the host docker socket so
# ko --local can publish into the host daemon. Mirrors cmd/calico/Makefile.
KO_RUN = $(DOCKER_RUN) -v /var/run/docker.sock:/var/run/docker.sock $(CALICO_BUILD)
else
CONTAINER_MARKER = .image.created-$(ARCH)
IMAGE_TAG = latest
KO_CONFIG = registrar.ko.yaml
KO_RUN =
endif

.PHONY: image image-all
image: $(CONTAINER_MARKER)

$(CONTAINER_MARKER): clone-registrar-upstream $(KO) $(KO_CONFIG)
	cp $(KO_CONFIG) $(REGISTRAR_IMAGE)/.ko.yaml
	$(KO_RUN) sh -c '\
	    unset GOOS GOARCH GOAMD64 && \
	    cd $(REGISTRAR_IMAGE) && \
	    GOTOOLCHAIN=$(GOTOOLCHAIN) \
	    KO_DEFAULTBASEIMAGE=$(CALICO_BASE) \
	    KO_DOCKER_REPO=$(REGISTRAR_IMAGE) $(REPO_ROOT)/bin/ko build \
	        --local --bare \
	        --platform=linux/$(ARCH) \
	        --tags=$(IMAGE_TAG)-$(ARCH) \
	        ./cmd/csi-node-driver-registrar'
ifeq ($(FIPS),true)
	# Verify the produced binary actually links the BoringCrypto module.
	# Mirrors the post-build check in cmd/calico/Makefile.
	mkdir -p $(BINDIR)
	cid=$$(docker create $(REGISTRAR_IMAGE):$(IMAGE_TAG)-$(ARCH)) && \
	    docker cp $$cid:/ko-app/csi-node-driver-registrar $(BINDIR)/registrar-fips-verify && \
	    docker rm $$cid >/dev/null
	$(DOCKER_GO_BUILD) sh -c \
	    "go tool nm $(BINDIR)/registrar-fips-verify | grep -q _Cfunc__goboringcrypto_"
	rm -f $(BINDIR)/registrar-fips-verify
endif
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=$(IMAGE_TAG) LATEST_IMAGE_TAG=$(IMAGE_TAG)
	touch $@

image-all: $(addprefix sub-image-,$(VALIDARCHES)) sub-image-fips-amd64
sub-image-%:
	$(MAKE) image ARCH=$*
sub-image-fips-%:
	$(MAKE) image FIPS=true ARCH=$*

###############################################################################
# CI/CD
###############################################################################
## Deploys images to registry.
.PHONY: cd
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of the registrar image at the specified version.
.PHONY: release-build
release-build: .release-$(VERSION).created
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)-fips LATEST_IMAGE_TAG=latest-fips
	$(MAKE) FIPS=true retag-build-images-with-registries RELEASE=true IMAGETAG=latest-fips LATEST_IMAGE_TAG=latest-fips
	touch $@

## Pushes the registrar image to the registries.
.PHONY: release-publish
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	$(MAKE) FIPS=true push-images-to-registries push-manifests IMAGETAG=$(VERSION)-fips RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - set VERSION=vX.Y.Z)
endif

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: $(SRC_FILES)
	mkdir -p report
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) sh -c 'set -o pipefail && cd /go/src/$(PACKAGE_NAME) && go test -v ./... | go-junit-report > ./report/tests.xml'

fv st:
	@echo "No FVs or STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download build clean-registrar static-checks ut
