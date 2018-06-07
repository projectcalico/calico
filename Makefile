###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=amd64 arm64 ppc64le s390x

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

GO_BUILD_VER ?= v0.15

HYPERKUBE_IMAGE?=gcr.io/google_containers/hyperkube-$(ARCH):v1.8.0-beta.1
ETCD_IMAGE ?= quay.io/coreos/etcd:v3.2.5-$(BUILDARCH)
# If building on amd64 omit the arch in the container name.
ifeq ($(BUILDARCH),amd64)
        ETCD_IMAGE=quay.io/coreos/etcd:v3.2.5
endif

.PHONY: all binary build test clean help image
default: help

# Makefile configuration options
CONTAINER_NAME=calico/kube-controllers
PACKAGE_NAME?=github.com/projectcalico/kube-controllers
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
LIBCALICOGO_PATH?=none
LOCAL_USER_ID?=$(shell id -u $$USER)

# Determine which OS.
OS?=$(shell uname -s | tr A-Z a-z)

# Get version from git.
GIT_VERSION?=$(shell git describe --tags --dirty)

DOCKER_GO_BUILD := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
                              -v $${PWD}:/go/src/github.com/projectcalico/kube-controllers:rw \
                              -v $${PWD}/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/github.com/projectcalico/kube-controllers \
                              $(CALICO_BUILD)

###############################################################################
# Build targets
###############################################################################
## Builds the controller binary and docker image.
image: image.created-$(ARCH)
image.created-$(ARCH): dist/kube-controllers-linux-$(ARCH)
	# Build the docker image for the policy controller.
	docker build -t $(CONTAINER_NAME):latest-$(ARCH) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	# Need amd64 builds tagged as :latest because Semaphore depends on that
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):latest
endif
	touch $@

image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

dist/kube-controllers-linux-$(ARCH):
	$(MAKE) OS=linux ARCH=$(ARCH) binary-containerized

# Populates the vendor directory.
.PHONY: vendor
vendor: vendor/.up-to-date
vendor/.up-to-date: glide.yaml
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \

	docker run --rm \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
		-v $(HOME)/.glide:/home/user/.glide:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		$(CALICO_BUILD) \
		/bin/sh -c 'cd /go/src/$(PACKAGE_NAME) && glide install -strip-vendor'
	touch vendor/.up-to-date

# Builds the controller binary.
binary: vendor
	# Don't try to "install" the intermediate build files (.a .o) when not on linux
	# since there are no write permissions for them in our linux build container.
	if [ "$(OS)" == "linux" ]; then \
		INSTALL_FLAG=" -i "; \
	fi; \
	GOOS=$(OS) GOARCH=$(ARCH) CGO_ENABLED=0 go build -v $$INSTALL_FLAG -o dist/kube-controllers-$(OS)-$(ARCH) \
	-ldflags "-X main.VERSION=$(GIT_VERSION)" ./main.go

## Builds the controller binary in a container.
.PHONY: build-all
build-all: $(addprefix sub-build-,$(ARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

build: dist/kube-controllers-linux-$(ARCH)
binary-containerized: vendor
	mkdir -p dist
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e OS=$(OS) -e ARCH=$(ARCH) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
	  -w /go/src/$(PACKAGE_NAME) \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
	  $(CALICO_BUILD) make OS=$(OS) ARCH=$(ARCH) binary

###############################################################################
# Test targets
###############################################################################

## Builds the code and runs all tests.
ci: clean image check-copyright ut fv

## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images push IMAGETAG=${BRANCH_NAME}
	$(MAKE) tag-images push IMAGETAG=$(shell git describe --tags --dirty --always --long)


## Run the unit tests in a container.
ut: vendor
	-mkdir -p .go-pkg-cache
	docker run --rm --privileged --net=host \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && WHAT=$(WHAT) SKIP=$(SKIP) ./run-uts'

.PHONY: fv
## Build and run the FV tests.
GINKGO_FOCUS?=.*
fv: tests/fv/fv.test image
	@echo Running Go FVs.
	cd tests/fv && ETCD_IMAGE=$(ETCD_IMAGE) HYPERKUBE_IMAGE=$(HYPERKUBE_IMAGE) CONTAINER_NAME=$(CONTAINER_NAME):latest-$(ARCH) ./fv.test -ginkgo.slowSpecThreshold 30 -ginkgo.focus $(GINKGO_FOCUS)

GET_CONTAINER_IP := docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
K8S_VERSION=1.7.5
## Runs system tests.
st: image run-etcd run-k8s-apiserver
	./tests/system/apiserver-reconnection.sh $(CONTAINER_NAME):latest-$(ARCH)
	$(MAKE) stop-k8s-apiserver stop-etcd

tests/fv/fv.test: $(shell find ./tests -type f -name '*.go' -print)
	# We pre-build the test binary so that we can run it outside a container and allow it
	# to interact with docker.
	$(DOCKER_GO_BUILD) go test ./tests/fv -c --tags fvtests -o tests/fv/fv.test

.PHONY: run-k8s-apiserver stop-k8s-apiserver run-etcd stop-etcd
run-k8s-apiserver: stop-k8s-apiserver
	ETCD_IP=`$(GET_CONTAINER_IP) st-etcd` && \
	docker run --detach \
	  --name st-apiserver \
	gcr.io/google_containers/hyperkube-$(ARCH):v$(K8S_VERSION) \
		  /hyperkube apiserver --etcd-servers=http://$${ETCD_IP}:2379 \
		  --service-cluster-ip-range=10.101.0.0/16 -v=10 \
		  --authorization-mode=RBAC

stop-k8s-apiserver:
	@-docker rm -f st-apiserver

run-etcd: stop-etcd
	docker run --detach \
	--name st-etcd $(ETCD_IMAGE) \
	etcd \
	--advertise-client-urls "http://127.0.0.1:2379,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

stop-etcd:
	@-docker rm -f st-etcd

# Make sure that a copyright statement exists on all go files.
check-copyright:
	./check-copyrights.sh

###############################################################################
# tag and push images of any tag
###############################################################################


# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## tag images of one arch
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)


###############################################################################
# Release targets
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

	$(MAKE) image
	$(MAKE) tag-images IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(CONTAINER_NAME):$(VERSION) -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CONTAINER_NAME):$(VERSION) -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CONTAINER_NAME):$(VERSION) -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CONTAINER_NAME):$(VERSION) -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	# Run FV tests against the produced image. We only run the subset tagged as release tests.
	$(MAKE) CONTAINER_NAME=$(CONTAINER_NAME):$(VERSION) GINKGO_FOCUS="Release" fv

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
	$(MAKE) push IMAGETAG=$(VERSION) ARCH=$(ARCH)

	@echo "Finalize the GitHub release based on the pushed tag."
	@echo ""
	@echo "  https://github.com/projectcalico/kube-controllers/releases/tag/$(VERSION)"
	@echo ""
	@echo "If this is the latest stable release, then run the following to push 'latest' images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish-latest"
	@echo ""

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(CONTAINER_NAME):latest -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CONTAINER_NAME):latest -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CONTAINER_NAME):latest -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CONTAINER_NAME):latest -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push IMAGETAG=latest ARCH=$(ARCH)

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

## Removes all build artifacts.
clean:
	rm -rf dist image.created-$(ARCH)
	-docker rmi $(CONTAINER_NAME)
	rm -f st-kubeconfig.yaml
	rm -f tests/fv/fv.test

###############################################################################
# Utilities
###############################################################################

.PHONY: help
## Display this help text.
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	$(info Available targets)
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

goimports:
	goimports -l -w ./pkg
	goimports -l -w ./main.go
