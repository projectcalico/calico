# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut

###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=$(patsubst Dockerfile.%,%,$(wildcard Dockerfile.*))

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

# Build mounts for running in "local build" mode. Mount in libcalico, but null out
# the vendor directory. This allows an easy build using local development code,
# assuming that there is a local checkout of libcalico in the same directory as this repo.
LOCAL_BUILD_MOUNTS ?=
ifeq ($(LOCAL_BUILD),true)
LOCAL_BUILD_MOUNTS = -v $(CURDIR)/../libcalico-go:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go:ro \
	-v $(CURDIR)/.empty:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go/vendor:ro
endif

# we want to be able to run the same recipe on multiple targets keyed on the image name
# to do that, we would use the entire image name, e.g. calico/node:abcdefg, as the stem, or '%', in the target
# however, make does **not** allow the usage of invalid filename characters - like / and : - in a stem, and thus errors out
# to get around that, we "escape" those characters by converting all : to --- and all / to ___ , so that we can use them
# in the target, we then unescape them back
escapefs = $(subst :,---,$(subst /,___,$(1)))
unescapefs = $(subst ---,:,$(subst ___,/,$(1)))

# these macros create a list of valid architectures for pushing manifests
space :=
space +=
comma := ,
prefix_linux = $(addprefix linux/,$(strip $1))
join_platforms = $(subst $(space),$(comma),$(call prefix_linux,$(strip $1)))

# list of arches *not* to build when doing *-all
#    until s390x works correctly
EXCLUDEARCH ?= s390x
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

###############################################################################
GO_BUILD_VER?=v0.20
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
PROTOC_VER?=v0.1
PROTOC_CONTAINER?=calico/protoc:$(PROTOC_VER)-$(BUILDARCH)

# Get version from git - used for releases.
GIT_VERSION?=$(shell git describe --tags --dirty --always)
ifeq ($(LOCAL_BUILD),true)
	GIT_VERSION = $(shell git describe --tags --dirty --always)-dev-build
endif

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
LOCAL_USER_ID:=$(shell id -u)
MY_GID:=$(shell id -g)

SRC_FILES=$(shell find -name '*.go' |grep -v vendor)

############################################################################
BUILD_IMAGE?=calico/dikastes
PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/dikastes
RELEASE_IMAGES?=gcr.io/projectcalico-org/dikastes eu.gcr.io/projectcalico-org/dikastes asia.gcr.io/projectcalico-org/dikastes us.gcr.io/projectcalico-org/dikastes
PACKAGE_NAME?=github.com/projectcalico/app-policy

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGES+=$(RELEASE_IMAGES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES ?= quay.io/
PUSH_MANIFEST_IMAGES=$(PUSH_IMAGES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGES=$(filter-out $(PUSH_MANIFEST_IMAGES),$(PUSH_IMAGES))

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

# Allow libcalico-go and the ssh auth sock to be mapped into the build container.
ifdef LIBCALICOGO_PATH
  EXTRA_DOCKER_ARGS += -v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro
endif
ifdef SSH_AUTH_SOCK
  EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif

 # Pre-configured docker run command that runs as this user with the repo
 # checked out to /code, uses the --rm flag to avoid leaving the container
 # around afterwards.
DOCKER_RUN_RM:=docker run --rm \
               $(EXTRA_DOCKER_ARGS) \
               --user $(LOCAL_USER_ID):$(MY_GID) -v $(CURDIR):/code

ENVOY_API=vendor/github.com/envoyproxy/data-plane-api
EXT_AUTH=$(ENVOY_API)/envoy/service/auth/v2alpha/
ADDRESS=$(ENVOY_API)/envoy/api/v2/core/address
V2_BASE=$(ENVOY_API)/envoy/api/v2/core/base
HTTP_STATUS=$(ENVOY_API)/envoy/type/http_status

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf report/
	# Only one pb.go file exists outside the vendor dir
	rm -rf bin vendor proto/felixbackend.pb.go
	-docker rmi $(BUILD_IMAGE):latest-$(ARCH)
	-docker rmi $(BUILD_IMAGE):$(VERSION)-$(ARCH)
ifeq ($(ARCH),amd64)
	-docker rmi $(BUILD_IMAGE):latest
	-docker rmi $(BUILD_IMAGE):$(VERSION)
endif
###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/dikastes-,$(VALIDARCHES))

.PHONY: build
## Build the binary for the current architecture and platform
build: bin/dikastes-$(ARCH) bin/healthz-$(ARCH)

## Create the vendor directory
vendor: glide.yaml
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	docker run --rm -i \
      -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
      -v $(HOME)/.glide:/home/user/.glide:rw \
      -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
      -w /go/src/$(PACKAGE_NAME) \
      $(CALICO_BUILD) glide install -strip-vendor

# Default the libcalico repo and version but allow them to be overridden
LIBCALICO_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
LIBCALICO_REPO?=github.com/projectcalico/libcalico-go
LIBCALICO_VERSION?=$(shell git ls-remote git@github.com:projectcalico/libcalico-go $(LIBCALICO_BRANCH) 2>/dev/null | cut -f 1)

## Update libcalico pin in glide.yaml
update-libcalico:
	docker run --rm -i \
          -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
          -v $(HOME)/.glide:/home/user/.glide:rw \
          -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
          -w /go/src/$(PACKAGE_NAME) \
          $(CALICO_BUILD) sh -c '\
        echo "Updating libcalico to $(LIBCALICO_VERSION) from $(LIBCALICO_REPO)"; \
        export OLD_VER=$$(grep --after 50 libcalico-go glide.yaml |grep --max-count=1 --only-matching --perl-regexp "version:\s*\K[\.0-9a-z]+") ;\
        echo "Old version: $$OLD_VER";\
        if [ $(LIBCALICO_VERSION) != $$OLD_VER ]; then \
            sed -i "s/$$OLD_VER/$(LIBCALICO_VERSION)/" glide.yaml && \
            if [ $(LIBCALICO_REPO) != "github.com/projectcalico/libcalico-go" ]; then \
              glide mirror set https://github.com/projectcalico/libcalico-go $(LIBCALICO_REPO) --vcs git; glide mirror list; \
            fi;\
          OUTPUT=`mktemp`;\
          glide up --strip-vendor 2>&1 | tee $$OUTPUT; \
          if ! grep "\[WARN\]" $$OUTPUT; then true; else false; fi; \
        fi'

bin/dikastes-amd64: ARCH=amd64
bin/dikastes-arm64: ARCH=arm64
bin/dikastes-ppc64le: ARCH=ppc64le
bin/dikastes-s390x: ARCH=s390x
bin/dikastes-%: vendor proto $(SRC_FILES)
	mkdir -p bin
	-mkdir -p .go-pkg-cache
	docker run --rm -ti \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
	  $(LOCAL_BUILD_MOUNTS) \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -e GOCACHE=/go-cache \
	  -w /go/src/$(PACKAGE_NAME) \
	  $(CALICO_BUILD) go build -ldflags "-X main.VERSION=$(GIT_VERSION) -s -w" -v -o bin/dikastes-$(ARCH)

bin/healthz-amd64: ARCH=amd64
bin/healthz-arm64: ARCH=arm64
bin/healthz-ppc64le: ARCH=ppc64le
bin/healthz-s390x: ARCH=s390x
bin/healthz-%: vendor proto $(SRC_FILES)
	mkdir -p bin || true
	-mkdir -p .go-pkg-cache || true
	docker run --rm -ti \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
	  $(LOCAL_BUILD_MOUNTS) \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -e GOCACHE=/go-cache \
	  -w /go/src/$(PACKAGE_NAME) \
	  $(CALICO_BUILD) go build -ldflags "-X main.VERSION=$(GIT_VERSION) -s -w" -v -o bin/healthz-$(ARCH) ./cmd/healthz

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

proto: $(EXT_AUTH)external_auth.pb.go $(ADDRESS).pb.go $(V2_BASE).pb.go $(HTTP_STATUS).pb.go $(EXT_AUTH)attribute_context.pb.go proto/felixbackend.pb.go proto/healthz.proto

$(EXT_AUTH)external_auth.pb.go $(EXT_AUTH)attribute_context.pb.go: $(EXT_AUTH)external_auth.proto $(EXT_AUTH)attribute_context.proto
	$(DOCKER_RUN_RM) -v $(CURDIR):/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              $(EXT_AUTH)*.proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(ADDRESS).pb.go $(V2_BASE).pb.go: $(ADDRESS).proto $(V2_BASE).proto
	$(DOCKER_RUN_RM) -v $(CURDIR):/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              $(ADDRESS).proto $(V2_BASE).proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(HTTP_STATUS).pb.go: $(HTTP_STATUS).proto
	$(DOCKER_RUN_RM) -v $(CURDIR):/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              $(HTTP_STATUS).proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):$(ENVOY_API)

$(EXT_AUTH)external_auth.proto $(ADDRESS).proto $(V2_BASE).proto $(HTTP_STATUS).proto $(EXT_AUTH)attribute_context.proto: vendor

proto/felixbackend.pb.go: proto/felixbackend.proto
	$(DOCKER_RUN_RM) -v $(CURDIR):/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              proto/*.proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):proto

proto/healthz.pb.go: proto/healthz.proto
	$(DOCKER_RUN_RM) -v $(CURDIR):/src:rw \
	              $(PROTOC_CONTAINER) \
	              $(PROTOC_IMPORTS) \
	              proto/*.proto \
	              --gogofast_out=plugins=grpc,$(PROTOC_MAPPINGS):proto


# Building the image
###############################################################################
CONTAINER_CREATED=.dikastes.created-$(ARCH)
.PHONY: image $(BUILD_IMAGE)
image: $(BUILD_IMAGE)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(BUILD_IMAGE): $(CONTAINER_CREATED)
$(CONTAINER_CREATED): Dockerfile.$(ARCH) bin/dikastes-$(ARCH) bin/healthz-$(ARCH)
	docker build -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif
	touch $@

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))
sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

push-all: imagetag $(addprefix sub-push-,$(VALIDARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## push multi-arch manifest where supported
push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using $(DOCKER_CONFIG) holds the docker login credentials
# path to credentials based on manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*:$(IMAGETAG))-ARCH --target $(call unescapefs,$*:$(IMAGETAG))"

## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))

sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(VALIDARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

###############################################################################
# Static checks
###############################################################################
## Perform static checks on the code.
.PHONY: static-checks
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) gometalinter --deadline=300s --disable-all --enable=goimports --vendor ./...

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRC_FILES)

foss-checks: vendor
	@echo Running $@...
	@docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -e FOSSA_API_KEY=$(FOSSA_API_KEY) \
	  -w /go/src/$(PACKAGE_NAME) \
	  $(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: proto
	mkdir -p report
	docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		$(LOCAL_BUILD_MOUNTS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) /bin/bash -c "go test -v ./... | go-junit-report > ./report/tests.xml"

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean build-all static-checks ut

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: image-all
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=${BRANCH_NAME} EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long) EXCLUDEARCH="$(EXCLUDEARCH)"

###############################################################################
# Release
###############################################################################
PREVIOUS_RELEASE=$(shell git describe --tags --abbrev=0)

## Tags and builds a release from start to finish.
release: release-prereqs
	$(MAKE) VERSION=$(VERSION) release-tag
	$(MAKE) VERSION=$(VERSION) release-build
	$(MAKE) VERSION=$(VERSION) release-verify

	@echo ""
	@echo "Release build complete. Next, push the produced images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish"
	@echo ""

## Produces a git tag for the release.
release-tag: release-prereqs release-notes
	git tag $(VERSION) -F release-notes-$(VERSION)
	@echo ""
	@echo "Now you can build the release:"
	@echo ""
	@echo "  make VERSION=$(VERSION) release-build"
	@echo ""

## Produces a clean build of release artifacts at the specified version.
release-build: release-prereqs clean
# Check that the correct code is checked out.
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif

	$(MAKE) image-all
	$(MAKE) tag-images-all IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images-all IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) /dikastes --version | grep '^$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) /dikastes --version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	# Push images.
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=$(VERSION)

	@echo "Finalize the GitHub release based on the pushed tag."
	@echo ""
	@echo "  https://$(PACKAGE_NAME)/releases/tag/$(VERSION)"
	@echo ""
	@echo "If this is the latest stable release, then run the following to push 'latest' images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish-latest"
	@echo ""

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: help
## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	@awk '/^[a-zA-Z\-\_0-9\/]+:/ {                                      \
		nb = sub( /^## /, "", helpMsg );                                \
		if(nb == 0) {                                                   \
			helpMsg = $$0;                                              \
			nb = sub( /^[^:]*:.* ## /, "", helpMsg );                   \
		}                                                               \
		if (nb)                                                         \
			printf "\033[1;31m%-" width "s\033[0m %s\n", $$1, helpMsg;  \
	}                                                                   \
	{ helpMsg = $$0 }'                                                  \
	width=20                                                            \
	$(MAKEFILE_LIST)

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks
