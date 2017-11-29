.PHONY: all binary test clean help
default: help
all: test                                            ## Run all the tests
test: test-containerized                             ## Run all the tests
all: dist/calico-upgrade dist/calico-upgrade-darwin-amd64 dist/calico-upgrade-windows-amd64.exe test-containerized

###############################################################################
# calico-upgrade build
# - Building the calico-upgrade binary in a container
# - Building the calico-upgrade binary outside a container ("simple-binary")
# - Building the calico/ctl image
###############################################################################
# Determine which OS / ARCH.
OS := $(shell uname -s | tr A-Z a-z)
ARCH := amd64
###############################################################################
# Subcomponent versions:
GO_BUILD_VER:=latest
###############################################################################

CALICO_UPGRADE_VERSION?=$(shell git describe --tags --dirty --always)
CALICO_UPGRADE_DIR=pkg
UPGRADE_CONTAINER_NAME?=calico/ctl
CALICO_UPGRADE_FILES=$(shell find $(CALICO_UPGRADE_DIR) -name '*.go')
UPGRADE_CONTAINER_CREATED=$(CALICO_UPGRADE_DIR)/.calico_upgrade.created

CALICO_UPGRADE_BUILD_DATE?=$(shell date -u +'%FT%T%z')
CALICO_UPGRADE_GIT_REVISION?=$(shell git rev-parse --short HEAD)

CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
LOCAL_USER_ID?=$(shell id -u $$USER)

PACKAGE_NAME?=github.com/projectcalico/calico/calico_upgrade

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/pkg/commands.VERSION=$(CALICO_UPGRADE_VERSION) \
	-X $(PACKAGE_NAME)/pkg/commands.BUILD_DATE=$(CALICO_UPGRADE_BUILD_DATE) \
	-X $(PACKAGE_NAME)/pkg/commands.GIT_REVISION=$(CALICO_UPGRADE_GIT_REVISION) -s -w"

LIBCALICOGO_PATH?=none

calico/upgrade: $(UPGRADE_CONTAINER_CREATED)      ## Create the calico/ctl image

.PHONY: clean-calico-upgrade
clean-calico-upgrade:
	docker rmi $(UPGRADE_CONTAINER_NAME):latest || true

# Use this to populate the vendor directory after checking out the repository.
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

# build calico_upgrade image
$(UPGRADE_CONTAINER_CREATED): pkg/Dockerfile.calico-upgrade dist/calico-upgrade
	docker build -t $(UPGRADE_CONTAINER_NAME) -f pkg/Dockerfile.calico-upgrade .
	touch $@

## Build calico-upgrade
binary: $(CALICO_UPGRADE_FILES) vendor
	# Don't try to "install" the intermediate build files (.a .o) when not on linux
	# since there are no write permissions for them in our linux build container.
	if [ "$(OS)" == "linux" ]; then \
		INSTALL_FLAG=" -i "; \
	fi; \
	GOOS=$(OS) GOARCH=$(ARCH) CGO_ENABLED=0 go build -v $$INSTALL_FLAG -o dist/calico-upgrade-$(OS)-$(ARCH) $(LDFLAGS) "./pkg/calicoupgrade.go"

dist/calico-upgrade: $(CALICO_UPGRADE_FILES) vendor
	$(MAKE) dist/calico-upgrade-linux-amd64
	mv dist/calico-upgrade-linux-amd64 dist/calico-upgrade

dist/calico-upgrade-linux-amd64: $(CALICO_UPGRADE_FILES) vendor
	$(MAKE) OS=linux ARCH=amd64 binary-containerized

dist/calico-upgrade-darwin-amd64: $(CALICO_UPGRADE_FILES) vendor
	$(MAKE) OS=darwin ARCH=amd64 binary-containerized

dist/calico-upgrade-windows-amd64.exe: $(CALICO_UPGRADE_FILES) vendor
	$(MAKE) OS=windows ARCH=amd64 binary-containerized
	mv dist/calico-upgrade-windows-amd64 dist/calico-upgrade-windows-amd64.exe

## Run the build in a container. Useful for CI
binary-containerized: $(CALICO_UPGRADE_FILES) vendor
	mkdir -p dist
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e OS=$(OS) -e ARCH=$(ARCH) \
	  -e CALICO_UPGRADE_VERSION=$(CALICO_UPGRADE_VERSION) \
	  -e CALICO_UPGRADE_BUILD_DATE=$(CALICO_UPGRADE_BUILD_DATE) -e CALICO_UPGRADE_GIT_REVISION=$(CALICO_UPGRADE_GIT_REVISION) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    -v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
	  $(CALICO_BUILD) sh -c '\
	    cd /go/src/$(PACKAGE_NAME) && \
	    make OS=$(OS) ARCH=$(ARCH) \
	         CALICO_UPGRADE_VERSION=$(CALICO_UPGRADE_VERSION)  \
	         CALICO_UPGRADE_BUILD_DATE=$(CALICO_UPGRADE_BUILD_DATE) CALICO_UPGRADE_GIT_REVISION=$(CALICO_UPGRADE_GIT_REVISION) \
	         binary'

.PHONY: install
install:
	CGO_ENABLED=0 go install $(PACKAGE_NAME)/calico_upgrade

###############################################################################
# calico-upgrade UTs
###############################################################################
.PHONY: ut
## Run the Unit Tests locally
ut: dist/calico-upgrade
	# Run tests in random order find tests recursively (-r).
	ginkgo -cover -r --skipPackage vendor pkg/*

	@echo
	@echo '+==============+'
	@echo '| All coverage |'
	@echo '+==============+'
	@echo
	@find ./pkg/ -iname '*.coverprofile' | xargs -I _ go tool cover -func=_

	@echo
	@echo '+==================+'
	@echo '| Missing coverage |'
	@echo '+==================+'
	@echo
	@find ./pkg/ -iname '*.coverprofile' | xargs -I _ go tool cover -func=_ | grep -v '100.0%'

PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: dist/calico-upgrade
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
ST_TO_RUN?=tests/st/pkg/test_crud.py
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

## Run the STs in a container
.PHONY: st
st: dist/calico-upgrade run-etcd-host
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# All of code under test is mounted into the container.
	#   - This also provides access to calico-upgrade and the docker client
	docker run --net=host --privileged \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           --rm -ti \
	           -v $(SOURCE_DIR):/code \
	           calico/test \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'

	$(MAKE) stop-etcd

## Etcd is used by the STs
.PHONY: run-etcd-host
run-etcd-host:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd \
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

	# Make sure that calico-upgrade builds cross-platform.
	$(MAKE) dist/calico-upgrade-darwin-amd64 dist/calico-upgrade-windows-amd64.exe

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	# Check to make sure the tag isn't "-dirty".
	if git describe --tags --dirty | grep dirty; \
	then echo current git working tree is "dirty". Make sure you do not have any uncommitted changes ;false; fi

	# Build the calico-upgrade binaries, as well as the calico/ctl and calico/node images.
	$(MAKE) dist/calico-upgrade dist/calico-upgrade-darwin-amd64 dist/calico-upgrade-windows-amd64.exe
	$(MAKE) calico/ctl

	# Check that the version output includes the version specified.
	# Tests that the "git tag" makes it into the binaries. Main point is to catch "-dirty" builds
	# Release is currently supported on darwin / linux only.
	if ! docker run $(UPGRADE_CONTAINER_NAME) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(UPGRADE_CONTAINER_NAME) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	# Retag images with corect version and quay
	docker tag $(UPGRADE_CONTAINER_NAME) $(UPGRADE_CONTAINER_NAME):$(VERSION)
	docker tag $(UPGRADE_CONTAINER_NAME) quay.io/$(UPGRADE_CONTAINER_NAME):$(VERSION)
	docker tag $(UPGRADE_CONTAINER_NAME) quay.io/$(UPGRADE_CONTAINER_NAME):latest

	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(UPGRADE_CONTAINER_NAME)
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" $(UPGRADE_CONTAINER_NAME):$(VERSION)

	@echo "\nNow push the tag and images. Then create a release on Github and"
	@echo "attach dist/calico-upgrade, dist/calico-upgrade-darwin-amd64, and dist/calico-upgrade-windows-amd64.exe binaries"
	@echo "\nAdd release notes for calico-upgrade. Use this command"
	@echo "to find commit messages for this release: git log --oneline <old_release_version>...$(VERSION)"
	@echo "git push origin $(VERSION)"
	@echo "docker push calico/ctl:$(VERSION)"
	@echo "docker push quay.io/calico/ctl:$(VERSION)"
	@echo "docker push calico/ctl:latest"
	@echo "docker push quay.io/calico/ctl:latest"
	@echo "See RELEASING.md for detailed instructions."

## Clean enough that a new release build will be clean
clean: clean-calico-upgrade
	find . -name '*.created' -exec rm -f {} +
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
