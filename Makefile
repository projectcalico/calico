# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut test-install-cni

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
###############################################################################
GO_BUILD_VER ?= v0.16

SRCFILES=calico.go $(wildcard utils/*.go) $(wildcard k8s/*.go) ipam/calico-ipam.go
TEST_SRCFILES=$(wildcard test_utils/*.go) $(wildcard calico_cni_*.go)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

# fail if unable to download
CURL=curl -sSf

K8S_VERSION=1.6.1
CNI_VERSION=v0.6.0

# Get version from git.
GIT_VERSION?=$(shell git describe --tags --dirty)
BUILD_IMAGE_ORG?=calico

# By default set the CNI_SPEC_VERSION to 0.3.1 for tests.
CNI_SPEC_VERSION?=0.3.1

BIN=bin/$(ARCH)
# Ensure that the bin directory is always created
MAKE_SURE_BIN_EXIST := $(shell mkdir -p $(BIN))
CALICO_BUILD?=$(BUILD_IMAGE_ORG)/go-build:$(GO_BUILD_VER)$(ARCHTAG)

PACKAGE_NAME?=github.com/projectcalico/cni-plugin

CONTAINER_NAME=calico/cni$(ARCHTAG)
DEPLOY_CONTAINER_MARKER=cni_deploy_container-$(ARCH).created

ETCD_VER=v3.3.7
ETCD_CONTAINER ?= quay.io/coreos/etcd:$(ETCD_VER)-$(BUILDARCH)
# If building on amd64 omit the arch in the container name.
ifeq ($(BUILDARCH),amd64)
        ETCD_CONTAINER=quay.io/coreos/etcd:$(ETCD_VER)
endif

LIBCALICOGO_PATH?=none

DATASTORE_TYPE?=etcdv3

LOCAL_USER_ID?=$(shell id -u $$USER)

.PHONY: clean
clean:
	rm -rf $(BIN) vendor $(DEPLOY_CONTAINER_MARKER) .go-pkg-cache k8s-install/scripts/install_cni.test

###############################################################################
# Building the binary
###############################################################################
build: $(BIN)/calico $(BIN)/calico-ipam
build-all: $(addprefix sub-build-,$(ARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

## Create the vendor directory
vendor: glide.yaml
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide

	# To build without Docker just run "glide install -strip-vendor"
	if [ "$(LIBCALICOGO_PATH)" != "none" ]; then \
          EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
    docker run --rm -i \
      -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
      -v $(HOME)/.glide:/home/user/.glide:rw \
      -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
      $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
          glide install -strip-vendor'

## Build the Calico network plugin and ipam plugins
$(BIN)/calico $(BIN)/calico-ipam: $(SRCFILES) vendor
	-mkdir -p .go-pkg-cache
	docker run --rm \
	-e ARCH=$(ARCH) \
	-e GOARCH=$(ARCH) \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	-v $(CURDIR)/$(BIN):/go/src/$(PACKAGE_NAME)/$(BIN) \
	-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			go build -v -o $(BIN)/calico -ldflags "-X main.VERSION=$(GIT_VERSION) -s -w" calico.go ; \
            go build -v -o $(BIN)/calico-ipam -ldflags "-X main.VERSION=$(GIT_VERSION) -s -w" ipam/calico-ipam.go'

###############################################################################
# Building the image
###############################################################################
image: $(DEPLOY_CONTAINER_MARKER)
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)

	# Push images to gcr.io, used by GKE.
	docker push gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push eu.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push asia.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push us.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)

	# Push images to gcr.io, used by GKE.
	docker push gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
	docker push eu.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
	docker push asia.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
	docker push us.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
endif

## push all archs
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## tag images of one arch
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)

	# Tag images for gcr.io, used by GKE.
	docker tag $(CONTAINER_NAME):latest-$(ARCH) gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) eu.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) asia.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) us.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)

	# Tag images for gcr.io, used by GKE.
	docker tag $(CONTAINER_NAME):latest-$(ARCH) gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) eu.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) asia.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) us.gcr.io/projectcalico-org/$(CONTAINER_NAME):$(IMAGETAG)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

$(DEPLOY_CONTAINER_MARKER): Dockerfile.$(ARCH) build fetch-cni-bins
	docker build -f Dockerfile.$(ARCH) -t $(CONTAINER_NAME):latest-$(ARCH) .
ifeq ($(ARCH),amd64)
	# Need amd64 builds tagged as :latest because Semaphore depends on that
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):latest
endif
	touch $@

.PHONY: fetch-cni-bins
fetch-cni-bins: $(BIN)/flannel $(BIN)/loopback $(BIN)/host-local $(BIN)/portmap $(BIN)/tuning

$(BIN)/flannel $(BIN)/loopback $(BIN)/host-local $(BIN)/portmap $(BIN)/tuning:
	mkdir -p $(BIN)
	$(CURL) -L --retry 5 https://github.com/containernetworking/plugins/releases/download/$(CNI_VERSION)/cni-plugins-$(ARCH)-$(CNI_VERSION).tgz | tar -xz -C $(BIN) ./flannel ./loopback ./host-local ./portmap ./tuning

###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd  /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --enable=vet --enable=errcheck --vendor -s test_utils ./...'

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRCFILES)

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks

###############################################################################
# Unit Tests
###############################################################################
## Run the unit tests.
ut: run-k8s-apiserver build $(BIN)/host-local
	# The tests need to run as root
	docker run --rm -t --privileged --net=host \
	-e ETCD_IP=$(LOCAL_IP_ENV) \
	-e LOCAL_USER_ID=0 \
	-e ARCH=$(ARCH) \
	-e PLUGIN=calico \
	-e BIN=$(BIN) \
	-e CNI_SPEC_VERSION=$(CNI_SPEC_VERSION) \
	-e DATASTORE_TYPE=$(DATASTORE_TYPE) \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	$(CALICO_BUILD) sh -c '\
			cd  /go/src/$(PACKAGE_NAME) && \
			ginkgo -cover -r -skipPackage vendor -skipPackage k8s-install'
	make stop-etcd

## Run the tests in a container (as root) for different CNI spec versions
## to make sure we don't break backwards compatibility.
.PHONY: test-cni-versions
test-cni-versions:
	for cniversion in "0.2.0" "0.3.1" ; do \
		make ut CNI_SPEC_VERSION=$$cniversion; \
	done

## Kubernetes apiserver used for tests
run-k8s-apiserver: stop-k8s-apiserver run-etcd
	docker run --detach --net=host \
	  --name calico-k8s-apiserver \
  	gcr.io/google_containers/hyperkube-$(ARCH):v$(K8S_VERSION) \
		  /hyperkube apiserver --etcd-servers=http://$(LOCAL_IP_ENV):2379 \
		  --service-cluster-ip-range=10.101.0.0/16

## Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f calico-k8s-apiserver

## Etcd is used by the tests
run-etcd: stop-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd $(ETCD_CONTAINER) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Stops calico-etcd containers
stop-etcd:
	@-docker rm -f calico-etcd

###############################################################################
# Install test
###############################################################################
# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
k8s-install/scripts/install_cni.test: vendor
	-mkdir -p .go-pkg-cache
	docker run --rm \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			go test ./k8s-install/scripts -c --tags install_cni_test -o ./k8s-install/scripts/install_cni.test'

.PHONY: test-install-cni
## Test the install-cni.sh script
test-install-cni: image k8s-install/scripts/install_cni.test
	cd k8s-install/scripts && CONTAINER_NAME=$(CONTAINER_NAME) ./install_cni.test

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks test-cni-versions image test-install-cni

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
	$(MAKE) image
	$(MAKE) tag-images IMAGETAG=$(VERSION)
	$(MAKE) tag-images IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	docker run --rm calico/cni:$(VERSION)-$(ARCH) calico -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm calico/cni:$(VERSION)-$(ARCH) calico -v` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )

	# TODO: Some sort of quick validation of the produced binaries.

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
	@echo "Attach the $(BIN)/calico and $(BIN)/calico-ipam binaries."
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
	# Check latest versions match.
	if ! docker run $(CONTAINER_NAME):latest-$(ARCH) calico -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CONTAINER_NAME):latest-$(ARCH) calico -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CONTAINER_NAME):latest-$(ARCH) calico -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CONTAINER_NAME):latest-$(ARCH) calico -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push IMAGETAG=latest ARCH=$(ARCH)

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
## Run kube-proxy
run-kube-proxy:
	-docker rm -f calico-kube-proxy
	docker run --name calico-kube-proxy -d --net=host --privileged gcr.io/google_containers/hyperkube:v$(K8S_VERSION) /hyperkube proxy --master=http://127.0.0.1:8080 --v=2

.PHONY: test-watch
## Run the unit tests, watching for changes.
test-watch: $(BIN)/calico $(BIN)/calico-ipam run-etcd run-k8s-apiserver
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo) watch -skipPackage k8s-install -skipPackage vendor

.PHONY: help
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
