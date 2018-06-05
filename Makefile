# Shortcut targets
default: build

## Build binaries for all platforms and architectures
all: build

## Run the tests for the current platform/architecture
test: ut st


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
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

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

# Determine which OS.
OS := $(shell uname -s | tr A-Z a-z)

###############################################################################
GO_BUILD_VER ?= v0.14

CALICOCTL_VERSION?=$(shell git describe --tags --dirty --always)
CALICOCTL_DIR=calicoctl
CTL_CONTAINER_NAME?=calico/ctl
CALICOCTL_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created-$(ARCH)

TEST_CONTAINER_NAME ?= calico/test

CALICOCTL_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)

GO_BUILD_CONTAINER?=calico/go-build:$(GO_BUILD_VER)-$(BUILDARCH)
LOCAL_USER_ID?=$(shell id -u $$USER)

PACKAGE_NAME?=github.com/projectcalico/calicoctl

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/calicoctl/commands.VERSION=$(CALICOCTL_VERSION) \
	-X $(PACKAGE_NAME)/calicoctl/commands.BUILD_DATE=$(CALICOCTL_BUILD_DATE) \
	-X $(PACKAGE_NAME)/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

LIBCALICOGO_PATH?=none

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf bin build certs *.tar vendor
	docker rmi $(CTL_CONTAINER_NAME):latest-$(ARCH) || true
	docker rmi $(CTL_CONTAINER_NAME):$(VERSION)-$(ARCH) || true
ifeq ($(ARCH),amd64)
	docker rmi $(CTL_CONTAINER_NAME):latest || true
	docker rmi $(CTL_CONTAINER_NAME):$(VERSION) || true
endif



###############################################################################
# Building the binary
###############################################################################
.PHONY: build
## Build the binaries for all architectures and platforms
build: $(addprefix bin/calicoctl-linux-,$(ARCHES)) bin/calicoctl-windows-amd64.exe bin/calicoctl-darwin-amd64

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
      $(GO_BUILD_CONTAINER) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
          glide install -strip-vendor'

# The supported different binary names. For each, ensure that an OS and ARCH is set
bin/calicoctl-%-amd64: ARCH=amd64
bin/calicoctl-%-arm64: ARCH=arm64
bin/calicoctl-%-ppc64le: ARCH=ppc64le
bin/calicoctl-%-s390x: ARCH=s390x
bin/calicoctl-darwin-amd64: OS=darwin
bin/calicoctl-windows-amd64: OS=windows
bin/calicoctl-linux-%: OS=linux

bin/calicoctl-%: $(CALICOCTL_FILES) vendor
	mkdir -p bin
	-mkdir -p .go-pkg-cache
	docker run --rm -ti \
	  -e OS=$(OS) -e ARCH=$(ARCH) \
	  -e GOOS=$(OS) -e GOARCH=$(ARCH) \
	  -e CALICOCTL_VERSION=$(CALICOCTL_VERSION) \
	  -e CALICOCTL_BUILD_DATE=$(CALICOCTL_BUILD_DATE) -e CALICOCTL_GIT_REVISION=$(CALICOCTL_GIT_REVISION) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
      -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
      -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
      -e GOCACHE=/go-cache \
	    $(GO_BUILD_CONTAINER) sh -c '\
          cd /go/src/$(PACKAGE_NAME) && \
          go build -v -o bin/calicoctl-$(OS)-$(ARCH) $(LDFLAGS) "./calicoctl/calicoctl.go"'

# Overrides for the binaries that need different output names
bin/calicoctl: bin/calicoctl-linux-amd64
	mv $< $@
bin/calicoctl-windows-amd64.exe: bin/calicoctl-windows-amd64
	mv $< $@

###############################################################################
# Building the image
###############################################################################
.PHONY: image calico/ctl
image: calico/ctl
calico/ctl: $(CTL_CONTAINER_CREATED)
$(CTL_CONTAINER_CREATED): Dockerfile.$(ARCH) bin/calicoctl-linux-$(ARCH)
	docker build -t $(CTL_CONTAINER_NAME):latest-$(ARCH) -f Dockerfile.$(ARCH) .
	touch $@


###############################################################################
# Static checks
###############################################################################
## Perform static checks on the code.
.PHONY: static-checks
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(GO_BUILD_CONTAINER) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --vendor ./...'

.PHONY: fix
## Fix static checks
fix:
	goimports -w calicoctl/*

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev.
ut: bin/calicoctl-linux-amd64
	docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(GO_BUILD_CONTAINER) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -cover -r --skipPackage vendor calicoctl/*'

###############################################################################
# STs
###############################################################################
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/calicoctl/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

.PHONY: st
## Run the STs in a container
st: bin/calicoctl-linux-amd64 run-etcd-host
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	docker run --net=host --privileged \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -t \
	           -v $(CURDIR):/code \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           $(TEST_CONTAINER_NAME) \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'

	$(MAKE) stop-etcd

## Etcd is used by the STs
# NOTE: https://quay.io/repository/coreos/etcd is available *only* for the following archs with the following tags:
# amd64: 3.2.5
# arm64: 3.2.5-arm64
# ppc64le: 3.2.5-ppc64le
# s390x is not available
COREOS_ETCD ?= quay.io/coreos/etcd:v3.2.5-$(ARCH)
ifeq ($(ARCH),amd64)
COREOS_ETCD = quay.io/coreos/etcd:v3.2.5
endif
.PHONY: run-etcd-host
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd \
	$(COREOS_ETCD) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

.PHONY: stop-etcd
stop-etcd:
	@-docker rm -f calico-etcd

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean build static-checks ut st calico/ctl


###############################################################################
# Release
###############################################################################
.PHONY: release
## Do a release
release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	# Check to make sure the tag isn't "-dirty".
	if git describe --tags --dirty | grep dirty; \
	then echo current git working tree is "dirty". Make sure you do not have any uncommitted changes ;false; fi

	# Build the calicoctl binaries, as well as the calico/ctl and calico/node images.
	$(MAKE) bin/calicoctl bin/calicoctl-darwin-amd64 bin/calicoctl-windows-amd64.exe
	$(MAKE) calico/ctl

	# Check that the version output includes the version specified.
	# Tests that the "git tag" makes it into the binaries. Main point is to catch "-dirty" builds
	# Release is currently supported on darwin / linux only.
	if ! docker run $(CTL_CONTAINER_NAME):latest-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(CTL_CONTAINER_NAME):latest-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	# Retag images with corect version and quay
	docker tag $(CTL_CONTAINER_NAME):latest-$(ARCH) $(CTL_CONTAINER_NAME):$(VERSION)-$(ARCH)
	docker tag $(CTL_CONTAINER_NAME):latest-$(ARCH) quay.io/$(CTL_CONTAINER_NAME):$(VERSION)-$(ARCH)
	docker tag $(CTL_CONTAINER_NAME):latest-$(ARCH) quay.io/$(CTL_CONTAINER_NAME):latest-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CTL_CONTAINER_NAME):latest-$(ARCH) $(CTL_CONTAINER_NAME):latest
	docker tag $(CTL_CONTAINER_NAME):latest-$(ARCH) $(CTL_CONTAINER_NAME):$(VERSION)
endif


	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME):latest-$(ARCH)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME):$(VERSION)-$(ARCH)

	@echo ""
	@echo "# Push the created tag to GitHub"
	@echo "  git push origin $(VERSION)"
	@echo ""
	@echo "# Now, create a GitHub release from the tag, add release notes, and attach the following binaries:"
	@echo "- bin/calicoctl"
	@echo "- bin/calicoctl-linux-amd64"
	@echo "- bin/calicoctl-linux-arm64"
	@echo "- bin/calicoctl-linux-ppc64le"
	@echo "- bin/calicoctl-linux-s390x"
	@echo "- bin/calicoctl-darwin-amd64"
	@echo "- bin/calicoctl-windows-amd64.exe"
	@echo "# To find commit messages for the release notes:  git log --oneline <old_release_version>...$(VERSION)"
	@echo ""
	@echo "# Now push the newly created release images."
	@echo "  docker push $(CTL_CONTAINER_NAME):$(VERSION)-$(ARCH)"
	@echo "  docker push quay.io/$(CTL_CONTAINER_NAME):$(VERSION)-$(ARCH)"
ifeq ($(ARCH),amd64)
	@echo "  docker push $(CTL_CONTAINER_NAME):$(VERSION)"
	@echo "  docker push quay.io/$(CTL_CONTAINER_NAME):$(VERSION)"
endif
	@echo ""
	@echo "# For the final release only, push the latest tag"
	@echo "# DO NOT PUSH THESE IMAGES FOR RELEASE CANDIDATES OR ALPHA RELEASES"
	@echo "  docker push $(CTL_CONTAINER_NAME):latest-$(ARCH)"
	@echo "  docker push quay.io/$(CTL_CONTAINER_NAME):latest-$(ARCH)"
ifeq ($(ARCH),amd64)
	@echo "  docker push $(CTL_CONTAINER_NAME):latest"
	@echo "  docker push quay.io/$(CTL_CONTAINER_NAME):latest"
endif
	@echo ""
	@echo "See RELEASING.md for detailed instructions."

.PHONY: help
## Display this help text
help: # Some kind of magic from https://gist.github.com/rcmachado/af3db315e31383502660
	@echo "calicoctl Makefile"
	@echo
	@echo "Dependencies: docker 1.12+; go 1.8+"
	@echo
	@echo "For some target, set ARCH=<target> OS=<os> to build for a given target architecture and OS."
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
	@echo
	@echo "-----------------------------------------"
	@echo "Building for $(OS)-$(ARCH) INSTALL_FLAG=$(INSTALL_FLAG)"
	@echo
	@echo "ARCH (target):          $(ARCH)"
	@echo "OS (target):            $(OS)"
	@echo "BUILDARCH (host):       $(BUILDARCH)"
	@echo "GO_BUILD_CONTAINER:     $(GO_BUILD_CONTAINER)"
	@echo "-----------------------------------------"
