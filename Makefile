###############################################################################
# The build architecture is select by setting the ARCH variable.
# For example: When building on ppc64le you could use ARCH=ppc64le make <....>.
# When ARCH is undefined it defaults to amd64.
ARCH?=amd64
ifeq ($(ARCH),amd64)
        ARCHTAG?=
endif

ifeq ($(ARCH),ppc64le)
        ARCHTAG:=-ppc64le
endif

HYPERKUBE_IMAGE?=gcr.io/google_containers/hyperkube-$(ARCH):v1.8.0-beta.1
ETCD_IMAGE?=quay.io/coreos/etcd:v3.2.5$(ARCHTAG)

.PHONY: all binary build test clean help image
default: help

# Makefile configuration options 
CONTAINER_NAME=calico/kube-controllers$(ARCHTAG)
PACKAGE_NAME?=github.com/projectcalico/kube-controllers
GO_BUILD_VER:=v0.8
CALICO_BUILD?=calico/go-build$(ARCHTAG):$(GO_BUILD_VER)
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
image: image.created$(ARCHTAG)
image.created$(ARCHTAG): dist/kube-controllers-linux-$(ARCH)
	# Build the docker image for the policy controller.
	docker build --pull -t $(CONTAINER_NAME) -f Dockerfile$(ARCHTAG) .
	touch $@

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
build: binary-containerized
binary-containerized: vendor
	mkdir -p dist
	-mkdir -p .go-pkg-cache
	docker run --rm \
	  -e OS=$(OS) -e ARCH=$(ARCH) \
	  -v $(CURDIR):/go/src/$(PACKAGE_NAME):ro \
	  -v $(CURDIR)/dist:/go/src/$(PACKAGE_NAME)/dist \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
	  $(CALICO_BUILD) sh -c '\
	    cd /go/src/$(PACKAGE_NAME) && \
	    make OS=$(OS) ARCH=$(ARCH) binary'

###############################################################################
# Test targets 
###############################################################################

## Builds the code and runs all tests.
ci: clean image check-copyright ut fv

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
fv: tests/fv/fv.test image
	@echo Running Go FVs.
	cd tests/fv && ETCD_IMAGE=$(ETCD_IMAGE) HYPERKUBE_IMAGE=$(HYPERKUBE_IMAGE) CONTAINER_NAME=$(CONTAINER_NAME) ./fv.test -ginkgo.slowSpecThreshold 30

GET_CONTAINER_IP := docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
K8S_VERSION=1.7.5
## Runs system tests.
st: image run-etcd run-k8s-apiserver
	./tests/system/apiserver-reconnection.sh $(ARCHTAG)
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
# Release targets 
###############################################################################
## Produces a git tag for the release.
release-tag: release-prereqs
	git tag $(VERSION)
	@echo ""
	@echo "Now you can build the release:"
	@echo ""
	@echo "  make release-build VERSION=$(VERSION)"
	@echo ""

## Produces a clean build of release artifacts at the specified version.
release-build: release-prereqs clean
# Check that the correct code is checked out.
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif

	$(MAKE) image
	docker tag $(CONTAINER_NAME) $(CONTAINER_NAME):$(VERSION)
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):$(VERSION)

	# Generate the `latest` images.
	docker tag $(CONTAINER_NAME) quay.io/$(CONTAINER_NAME):latest

	@echo "Now verify the release and push the git tag and artifacts:"
	@echo ""
	@echo "  make release-verify release-publish VERSION=$(VERSION)"
	@echo ""
	@echo "If this is the latest stable release, also push latest images:"
	@echo ""
	@echo "  make release-publish-latest VERSION=$(VERSION)" 

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run calico/kube-controllers:$(VERSION) -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run calico/kube-controllers:$(VERSION) -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/calico/kube-controllers:$(VERSION) -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/calico/kube-controllers:$(VERSION) -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	# Run FV tests against the produced image.
	$(MAKE) CONTAINER_NAME=calico/kube-controllers:$(VERSION) st

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	# Push images.
	docker push calico/kube-controllers:$(VERSION)
	docker push quay.io/calico/kube-controllers:$(VERSION)

	# Make a draft of the release notes.
	$(MAKE) release-notes

	@echo "Complete the release process on GitHub"

# Run gren in a container in order to generate a GitHub release with the correct
# release notes. See here for more info: https://github.com/github-tools/github-release-notes
release-notes: release-prereqs
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN is undefined - run using make release-notes GITHUB_TOKEN=X)
endif
	docker run -ti --rm \
		-v $(PWD):/code \
		-e GREN_GITHUB_TOKEN=$(GITHUB_TOKEN) \
		-e VERSION=$(VERSION) \
		node bash -c "npm install github-release-notes -g && cd /code && gren release -d -t $(VERSION)"

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run calico/kube-controllers:latest -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run calico/kube-controllers:latest -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/calico/kube-controllers:latest -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/calico/kube-controllers:latest -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	docker push calico/kube-controllers:latest
	docker push quay.io/calico/kube-controllers:latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

## Removes all build artifacts.
clean:
	rm -rf dist image.created$(ARCHTAG)
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
