.PHONY: all binary test clean help
default: help
all: dist/calicoctl dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe test
test: test-containerized st                             ## Run all the tests

###############################################################################
# calicoctl build
# - Building the calicoctl binary in a container
# - Building the calicoctl binary outside a container ("simple-binary")
# - Building the calico/ctl image
###############################################################################

###############################################################################
# The build architecture is select by setting the ARCH variable.
# For example: When building on ppc64le you could use ARCH=ppc64le make <....>.
# When ARCH is undefined it defaults to amd64.
ARCH?=amd64
ifeq ($(ARCH),amd64)
	ARCHTAG?=
	GO_BUILD_VER:=v0.9
endif

ifeq ($(ARCH),ppc64le)
	ARCHTAG:=-ppc64le
	GO_BUILD_VER:=latest
endif

# Determine which OS.
OS := $(shell uname -s | tr A-Z a-z)

###############################################################################

CALICOCTL_VERSION?=$(shell git describe --tags --dirty --always)
CALICOCTL_DIR=calicoctl
CTL_CONTAINER_NAME?=calico/ctl$(ARCHTAG)
CALICOCTL_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created-$(ARCH)

CALICOCTL_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)

CALICO_BUILD?=calico/go-build$(ARCHTAG):$(GO_BUILD_VER)
LOCAL_USER_ID?=$(shell id -u $$USER)

PACKAGE_NAME?=github.com/projectcalico/calicoctl

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/calicoctl/commands.VERSION=$(CALICOCTL_VERSION) \
	-X $(PACKAGE_NAME)/calicoctl/commands.BUILD_DATE=$(CALICOCTL_BUILD_DATE) \
	-X $(PACKAGE_NAME)/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

LIBCALICOGO_PATH?=none

calico/ctl: $(CTL_CONTAINER_CREATED)      ## Create the calico/ctl image

.PHONY: clean-calicoctl
clean-calicoctl:
	docker rmi $(CTL_CONTAINER_NAME):latest || true

#Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor: glide.yaml
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
    $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/$(PACKAGE_NAME) && \
      glide install -strip-vendor'

# build calico_ctl image
$(CTL_CONTAINER_CREATED): calicoctl/Dockerfile.calicoctl$(ARCHTAG) dist/calicoctl
	docker build -t $(CTL_CONTAINER_NAME) -f calicoctl/Dockerfile.calicoctl$(ARCHTAG) .
	touch $@

## Build calicoctl
binary: $(CALICOCTL_FILES) vendor
	# Don't try to "install" the intermediate build files (.a .o) when not on linux
	# since there are no write permissions for them in our linux build container.
	if [ "$(OS)" == "linux" ]; then \
		INSTALL_FLAG=" -i "; \
	fi; \
	GOOS=$(OS) GOARCH=$(ARCH) CGO_ENABLED=0 go build -v $$INSTALL_FLAG -o dist/calicoctl-$(OS)-$(ARCH) $(LDFLAGS) "./calicoctl/calicoctl.go"

dist/calicoctl: $(CALICOCTL_FILES) vendor
	$(MAKE) dist/calicoctl-linux-$(ARCH)
	cp dist/calicoctl-linux-$(ARCH) dist/calicoctl

dist/calicoctl-linux-amd64: $(CALICOCTL_FILES) vendor
	$(MAKE) OS=linux ARCH=amd64 ARCHTAG=$(ARCHTAG) binary-containerized

dist/calicoctl-linux-ppc64le: $(CALICOCTL_FILES) vendor
	$(MAKE) OS=linux ARCH=ppc64le ARCHTAG=$(ARCHTAG) binary-containerized

dist/calicoctl-darwin-amd64: $(CALICOCTL_FILES) vendor
	$(MAKE) OS=darwin ARCH=amd64 ARCHTAG=$(ARCHTAG) binary-containerized

dist/calicoctl-windows-amd64.exe: $(CALICOCTL_FILES) vendor
	$(MAKE) OS=windows ARCH=amd64 ARCHTAG=$(ARCHTAG) binary-containerized
	mv dist/calicoctl-windows-amd64 dist/calicoctl-windows-amd64.exe

## Run the build in a container. Useful for CI
binary-containerized: $(CALICOCTL_FILES) vendor
	mkdir -p dist
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e OS=$(OS) -e ARCH=$(ARCH) \
	  -e CALICOCTL_VERSION=$(CALICOCTL_VERSION) \
	  -e CALICOCTL_BUILD_DATE=$(CALICOCTL_BUILD_DATE) -e CALICOCTL_GIT_REVISION=$(CALICOCTL_GIT_REVISION) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    -v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
	  $(CALICO_BUILD) sh -c '\
	    cd /go/src/$(PACKAGE_NAME) && \
	    make OS=$(OS) ARCH=$(ARCH) \
	         CALICOCTL_VERSION=$(CALICOCTL_VERSION)  \
	         CALICOCTL_BUILD_DATE=$(CALICOCTL_BUILD_DATE) CALICOCTL_GIT_REVISION=$(CALICOCTL_GIT_REVISION) \
	         binary'

.PHONY: install
install:
	CGO_ENABLED=0 go install $(PACKAGE_NAME)/calicoctl

###############################################################################
# calicoctl UTs
###############################################################################
.PHONY: ut
## Run the Unit Tests locally
ut: dist/calicoctl
	# Run tests in random order find tests recursively (-r).
	ginkgo -cover -r --skipPackage vendor calicoctl/*

	@echo
	@echo '+==============+'
	@echo '| All coverage |'
	@echo '+==============+'
	@echo
	@find ./calicoctl/ -iname '*.coverprofile' | xargs -I _ go tool cover -func=_

	@echo
	@echo '+==================+'
	@echo '| Missing coverage |'
	@echo '+==================+'
	@echo
	@find ./calicoctl/ -iname '*.coverprofile' | xargs -I _ go tool cover -func=_ | grep -v '100.0%'

PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: dist/calicoctl
	docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && make ut'

## Perform static checks on the code. The golint checks are allowed to fail, the others must pass.
.PHONY: static-checks
static-checks: vendor
	# vet and errcheck are disabled since they find problems...
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			gometalinter --deadline=300s --disable-all --enable=goimports --vendor ./...'


SOURCE_DIR?=$(dir $(lastword $(MAKEFILE_LIST)))
SOURCE_DIR:=$(abspath $(SOURCE_DIR))
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/calicoctl/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

## Run the STs in a container
.PHONY: st
st: dist/calicoctl run-etcd-host
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	docker run --net=host --privileged \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -t \
	           -v $(SOURCE_DIR):/code \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           calico/test$(ARCHTAG) \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'

	$(MAKE) stop-etcd

## Etcd is used by the STs
.PHONY: run-etcd-host
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:v3.2.5$(ARCHTAG) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

.PHONY: stop-etcd
stop-etcd:
	@-docker rm -f calico-etcd

# This depends on clean to ensure that dependent images get untagged and repulled
.PHONY: semaphore
semaphore: clean
	# Clean up unwanted files to free disk space.
	bash -c 'rm -rf /home/runner/{.npm,.phpbrew,.phpunit,.kerl,.kiex,.lein,.nvm,.npm,.phpbrew,.rbenv} /usr/local/golang /var/lib/mongodb'

	# Run the containerized tests first.
	$(MAKE) test-containerized st

	$(MAKE) calico/ctl

ifeq ($(ARCH),amd64)
		# Make sure that calicoctl builds cross-platform on amd64.
		$(MAKE) dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe
endif

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	# Check to make sure the tag isn't "-dirty".
	if git describe --tags --dirty | grep dirty; \
	then echo current git working tree is "dirty". Make sure you do not have any uncommitted changes ;false; fi

	# Build the calicoctl binaries, as well as the calico/ctl and calico/node images.
	$(MAKE) dist/calicoctl dist/calicoctl-darwin-amd64 dist/calicoctl-windows-amd64.exe
	$(MAKE) calico/ctl

	# Check that the version output includes the version specified.
	# Tests that the "git tag" makes it into the binaries. Main point is to catch "-dirty" builds
	# Release is currently supported on darwin / linux only.
	if ! docker run $(CTL_CONTAINER_NAME) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(CTL_CONTAINER_NAME) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	# Retag images with corect version and quay
	docker tag $(CTL_CONTAINER_NAME) $(CTL_CONTAINER_NAME):$(VERSION)
	docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):$(VERSION)
	docker tag $(CTL_CONTAINER_NAME) quay.io/$(CTL_CONTAINER_NAME):latest

	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(CTL_CONTAINER_NAME):$(VERSION)

	@echo ""
	@echo "# Push the created tag to GitHub"
	@echo "  git push origin $(VERSION)"
	@echo ""
	@echo "# Now, create a GitHub release from the tag, add release notes, and attach the following binaries:"
	@echo "- dist/calicoctl"
	@echo "- dist/calicoctl-darwin-amd64"
	@echo "- dist/calicoctl-windows-amd64.exe"
	@echo "# To find commit messages for the release notes:  git log --oneline <old_release_version>...$(VERSION)"
	@echo ""
	@echo "# Now push the newly created release images."
	@echo "  docker push calico/ctl:$(VERSION)"
	@echo "  docker push quay.io/calico/ctl:$(VERSION)"
	@echo ""
	@echo "# For the final release only, push the latest tag"
	@echo "# DO NOT PUSH THESE IMAGES FOR RELEASE CANDIDATES OR ALPHA RELEASES" 
	@echo "  docker push calico/ctl:latest"
	@echo "  docker push quay.io/calico/ctl:latest"
	@echo ""
	@echo "See RELEASING.md for detailed instructions."

## Clean enough that a new release build will be clean
clean: clean-calicoctl
	find . -name '*.created-$(ARCH)' -exec rm -f {} +
	rm -rf dist build certs *.tar vendor

.PHONY: help
## Display this help text
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
	@echo "Building for $(OS)-$(ARCH) INSTALL_FLAG=$(INSTALL_FLAG). Use: ARCH=xyz make <...> to change the build architecture."
