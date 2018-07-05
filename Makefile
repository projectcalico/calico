# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: fv st

##############################################################################
# The build architecture is select by setting the ARCH variable.
# # For example: When building on ppc64le you could use ARCH=ppc64le make <....>.
# # When ARCH is undefined it defaults to amd64.
ARCH?=amd64
ifeq ($(ARCH),amd64)
	ARCHTAG?=
endif

ifeq ($(ARCH),ppc64le)
	ARCHTAG:=-ppc64le
endif

ifeq ($(ARCH),s390x)
	ARCHTAG:=-s390x
endif
###############################################################################
GO_BUILD_VER?=v0.16
CALICO_BUILD?=calico/go-build$(ARCHTAG):$(GO_BUILD_VER)

# Version of this repository as reported by git.
CALICO_GIT_VER := $(shell git describe --tags --dirty --always)

# Versions and location of dependencies used in the build.
BIRD_VER?=v0.3.2
BIRD_URL?=https://github.com/projectcalico/calico-bird/releases/download/$(BIRD_VER)/bird
BIRD6_URL?=https://github.com/projectcalico/calico-bird/releases/download/$(BIRD_VER)/bird6
BIRDCL_URL?=https://github.com/projectcalico/calico-bird/releases/download/$(BIRD_VER)/birdcl

# Versions and locations of dependencies used in tests.
CALICOCTL_VER?=master
CNI_VER?=master
RR_VER?=master
TEST_CONTAINER_NAME_VER?=latest
CTL_CONTAINER_NAME?=calico/ctl$(ARCHTAG):$(CALICOCTL_VER)
RR_CONTAINER_NAME?=calico/routereflector$(ARCHTAG)
TEST_CONTAINER_NAME?=calico/test$(ARCHTAG):$(TEST_CONTAINER_NAME_VER)
ETCD_VERSION?=v3.3.7
ETCD_IMAGE?=quay.io/coreos/etcd:$(ETCD_VERSION)$(ARCHTAG)
K8S_VERSION?=v1.10.4
HYPERKUBE_IMAGE?=gcr.io/google_containers/hyperkube-$(ARCH):$(K8S_VERSION)
TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created')

# Variables used by the tests
CRD_PATH=$(CURDIR)/vendor/github.com/projectcalico/libcalico-go/test/
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=
# curl should failed on 404
CURL=curl -sSf

# Variables controlling the calico/node image
NODE_CONTAINER_NAME?=calico/node$(ARCHTAG)
NODE_CONTAINER_CREATED=.calico_node.created
NODE_CONTAINER_BIN_DIR=./filesystem/bin
NODE_CONTAINER_BINARIES=bird bird6 birdcl calico-node

# Variables for building the local binaries that go into calico/node
MAKE_SURE_BIN_EXIST := $(shell mkdir -p dist .go-pkg-cache $(NODE_CONTAINER_BIN_DIR))
NODE_CONTAINER_FILES=$(shell find ./filesystem -type f)
SRCFILES=$(shell find ./pkg -name '*.go')
LOCAL_USER_ID?=$(shell id -u $$USER)
LDFLAGS=-ldflags "-X main.VERSION=$(CALICO_GIT_VER)"
PACKAGE_NAME?=github.com/projectcalico/node
LIBCALICOGO_PATH?=none

# Variables for controlling image tagging and pushing.
DOCKER_REPOS=calico quay.io/calico
ifeq ($(RELEASE),true)
# If this is a release, also tag and push GCR images. 
DOCKER_REPOS+=gcr.io/projectcalico-org eu.gcr.io/projectcalico-org asia.gcr.io/projectcalico.org us.gcr.io/projectcalico.org
endif

## Clean enough that a new release build will be clean
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf certs *.tar vendor $(NODE_CONTAINER_BIN_DIR)

	# Delete images that we built in this repo
	docker rmi $(NODE_CONTAINER_NAME):latest-$(ARCH) || true
	docker rmi $(TEST_CONTAINER_NAME) || true

###############################################################################
# Building the binary
###############################################################################
build:  $(NODE_CONTAINER_BIN_DIR)/calico-node 
# Use this to populate the vendor directory after checking out the repository.
# To update upstream dependencies, delete the glide.lock file first.
vendor: glide.lock
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

$(NODE_CONTAINER_BIN_DIR)/calico-node: vendor
	docker run --rm \
		-e GOARCH=$(ARCH) \
		-e GOOS=linux \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
		-e GOCACHE=/go-cache \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/$(PACKAGE_NAME) && \
			go build -v -o $@ $(LDFLAGS) ./cmd/calico-node/main.go'

###############################################################################
# Building the image
###############################################################################
## Create the calico/node image.
image: $(NODE_CONTAINER_NAME)
$(NODE_CONTAINER_NAME): $(NODE_CONTAINER_CREATED)
$(NODE_CONTAINER_CREATED): ./Dockerfile$(ARCHTAG) $(NODE_CONTAINER_FILES) $(addprefix $(NODE_CONTAINER_BIN_DIR)/,$(NODE_CONTAINER_BINARIES))
	# Check versions of the binaries that we're going to use to build calico/node.
	# Since the binaries are built for Linux, run them in a container to allow the
	# make target to be run on different platforms (e.g. MacOS).
	docker run --rm -v $(CURDIR)/$(NODE_CONTAINER_BIN_DIR):/go/bin:rw $(CALICO_BUILD) /bin/sh -c "\
	  echo; echo calico-node -v;         /go/bin/calico-node -v; \
	  echo; echo bird --version;         /go/bin/bird --version; \
	"
	docker build --pull -t $(NODE_CONTAINER_NAME):latest-$(ARCH) . --build-arg ver=$(CALICO_GIT_VER) -f ./Dockerfile$(ARCHTAG)
	touch $@

# Get bird binaries
$(NODE_CONTAINER_BIN_DIR)/bird:
	$(CURL) -L $(BIRD_URL) -o $@
	chmod +x $(@D)/*
$(NODE_CONTAINER_BIN_DIR)/bird6:
	$(CURL) -L $(BIRD6_URL) -o $(@D)/bird6
	chmod +x $(@D)/*
$(NODE_CONTAINER_BIN_DIR)/birdcl:
	$(CURL) -L $(BIRDCL_URL) -o $(@D)/birdcl
	chmod +x $(@D)/*

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	for r in $(DOCKER_REPOS); do docker push $$r/node:$(IMAGETAG)-$(ARCH); done
ifeq ($(ARCH),amd64)
	for r in $(DOCKER_REPOS); do docker push $$r/node:$(IMAGETAG); done
endif

push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## tag images of one arch
tag-images: imagetag
	for r in $(DOCKER_REPOS); do docker tag $(NODE_CONTAINER_NAME):latest-$(ARCH) $$r/node:$(IMAGETAG)-$(ARCH); done
ifeq ($(ARCH),amd64)
	for r in $(DOCKER_REPOS); do docker tag $(NODE_CONTAINER_NAME):latest-$(ARCH) $$r/node:$(IMAGETAG); done
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

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
			gometalinter --deadline=300s --disable-all --enable=goimports --vendor pkg/...'

.PHONY: fix
## Fix static checks
fix:
	goimports -w $(SRCFILES)

###############################################################################
# FV Tests
###############################################################################
## Run the ginkgo FVs
fv: vendor run-k8s-apiserver
	docker run --rm \
	-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	--net=host \
	$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -cover -r -skipPackage vendor pkg/startup pkg/allocateipip'

# etcd is used by the STs
.PHONY: run-etcd
run-etcd:
	@-docker rm -f calico-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd $(ETCD_IMAGE) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379" \
	--listen-client-urls "http://0.0.0.0:2379"

# Kubernetes apiserver used for tests
run-k8s-apiserver: stop-k8s-apiserver run-etcd
	docker run \
		--net=host --name st-apiserver \
		-v  $(CRD_PATH):/manifests \
		--detach \
		${HYPERKUBE_IMAGE} \
		/hyperkube apiserver \
			--bind-address=0.0.0.0 \
			--insecure-bind-address=0.0.0.0 \
				--etcd-servers=http://127.0.0.1:2379 \
			--admission-control=NamespaceLifecycle,LimitRanger,DefaultStorageClass,ResourceQuota \
			--authorization-mode=RBAC \
			--service-cluster-ip-range=10.101.0.0/16 \
			--v=10 \
			--logtostderr=true

	# Wait until we can configure a cluster role binding which allows anonymous auth.
	while ! docker exec st-apiserver kubectl create \
		clusterrolebinding anonymous-admin \
		--clusterrole=cluster-admin \
		--user=system:anonymous; \
		do echo "Trying to create ClusterRoleBinding"; \
		sleep 1; \
		done

	# Create CustomResourceDefinition (CRD) for Calico resources
	# from the manifest crds.yaml
	while ! docker exec st-apiserver kubectl \
		apply -f /manifests/crds.yaml; \
		do echo "Trying to create CRDs"; \
		sleep 1; \
		done

# Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f st-apiserver

###############################################################################
# System tests
# - Support for running etcd (both securely and insecurely)
###############################################################################
# Pull calicoctl and CNI plugin binaries with versions as per XXX_VER
# variables.  These are used for the STs.
dist/calicoctl:
	-docker rm -f calicoctl
	docker pull $(CTL_CONTAINER_NAME)
	docker create --name calicoctl $(CTL_CONTAINER_NAME)
	docker cp calicoctl:calicoctl dist/calicoctl && \
	  test -e dist/calicoctl && \
	  touch dist/calicoctl
	-docker rm -f calicoctl

dist/calico-cni-plugin dist/calico-ipam-plugin:
	-docker rm -f calico-cni
	docker pull calico/cni:$(CNI_VER)
	docker create --name calico-cni calico/cni:$(CNI_VER)
	docker cp calico-cni:/opt/cni/bin/calico dist/calico-cni-plugin && \
	  test -e dist/calico-cni-plugin && \
	  touch dist/calico-cni-plugin
	docker cp calico-cni:/opt/cni/bin/calico-ipam dist/calico-ipam-plugin && \
	  test -e dist/calico-ipam-plugin && \
	  touch dist/calico-ipam-plugin
	-docker rm -f calico-cni

# Create images for containers used in the tests
busybox.tar:
	docker pull $(ARCH)/busybox:latest
	docker save --output busybox.tar $(ARCH)/busybox:latest

routereflector.tar:
	-docker pull calico/routereflector$(ARCHTAG):$(RR_VER)
	docker save --output routereflector.tar calico/routereflector$(ARCHTAG):$(RR_VER)

workload.tar:
	cd workload && docker build -t workload -f Dockerfile$(ARCHTAG) .
	docker save --output workload.tar workload

stop-etcd:
	@-docker rm -f calico-etcd

IPT_ALLOW_ETCD:=-A INPUT -i docker0 -p tcp --dport 2379 -m comment --comment "calico-st-allow-etcd" -j ACCEPT

# Create the calico/test image
test_image: calico_test.created 
calico_test.created: $(TEST_CONTAINER_FILES)
	cd calico_test && docker build -f Dockerfile$(ARCHTAG).calico_test -t $(TEST_CONTAINER_NAME) .
	touch calico_test.created

calico-node.tar: $(NODE_CONTAINER_CREATED)
	# Check versions of the Calico binaries that will be in calico-node.tar.
	# Since the binaries are built for Linux, run them in a container to allow the
	# make target to be run on different platforms (e.g. MacOS).
	docker run --rm $(NODE_CONTAINER_NAME):latest-$(ARCH) /bin/sh -c "\
	  echo bird --version;         /bin/bird --version; \
	"
	docker save --output $@ $(NODE_CONTAINER_NAME):latest-$(ARCH)

.PHONY: st-checks
st-checks:
	# Check that we're running as root.
	test `id -u` -eq '0' || { echo "STs must be run as root to allow writes to /proc"; false; }

	# Insert an iptables rule to allow access from our test containers to etcd
	# running on the host.
	iptables-save | grep -q 'calico-st-allow-etcd' || iptables $(IPT_ALLOW_ETCD)

.PHONY: st
## Run the system tests 
st: dist/calicoctl busybox.tar routereflector.tar calico-node.tar workload.tar run-etcd calico_test.created dist/calico-cni-plugin dist/calico-ipam-plugin
	# Check versions of Calico binaries that ST execution will use.
	docker run --rm -v $(CURDIR)/dist:/go/bin:rw $(CALICO_BUILD) /bin/sh -c "\
	  echo; echo calicoctl --version;        /go/bin/calicoctl --version; \
	  echo; echo calico-cni-plugin -v;       /go/bin/calico-cni-plugin -v; \
	  echo; echo calico-ipam-plugin -v;      /go/bin/calico-ipam-plugin -v; echo; \
	"
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# HOST_CHECKOUT_DIR is used for volume mounts on containers started by this one.
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	# $(MAKE) st-checks
	docker run --uts=host \
	           --pid=host \
	           --net=host \
	           --privileged \
	           -v $(CURDIR):/code \
	           -e HOST_CHECKOUT_DIR=$(CURDIR) \
	           -e DEBUG_FAILURES=$(DEBUG_FAILURES) \
	           -e MY_IP=$(LOCAL_IP_ENV) \
	           -e NODE_CONTAINER_NAME=$(NODE_CONTAINER_NAME):latest-$(ARCH) \
	           -e RR_CONTAINER_NAME=$(RR_CONTAINER_NAME):$(RR_VER) \
	           --rm -t \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           $(TEST_CONTAINER_NAME) \
	           sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: static-checks fv $(NODE_CONTAINER_NAME) st

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
GIT_VERSION?=$(shell git describe --tags --dirty)
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
	$(MAKE) tag-images RELEASE=true IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images RELEASE=true IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(NODE_CONTAINER_NAME):$(VERSION) versions | grep '^calico\/node $(VERSION)'; then echo "Reported version:" `docker run $(NODE_CONTAINER_NAME):$(VERSION) versions` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(NODE_CONTAINER_NAME):$(VERSION) versions | grep '^calico\/node $(VERSION)'; then echo "Reported version:" `docker run quay.io/$(NODE_CONTAINER_NAME):$(VERSION) versions` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	echo "" > release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	# Push images.
	$(MAKE) push RELEASE=true IMAGETAG=$(VERSION) ARCH=$(ARCH)

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
	# Check latest versions match.
	if ! docker run $(NODE_CONTAINER_NAME):latest-$(ARCH) versions | grep '^calico\/node $(VERSION)'; then echo "Reported version:" `docker run $(NODE_CONTAINER_NAME):latest-$(ARCH) versions` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(NODE_CONTAINER_NAME):latest-$(ARCH) versions | grep '^calico\/node $(VERSION)'; then echo "Reported version:" `docker run quay.io/$(NODE_CONTAINER_NAME):latest-$(ARCH) versions` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push RELEASE=true IMAGETAG=latest ARCH=$(ARCH)

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

###############################################################################
# Release
###############################################################################

.PHONY: node-test-at
# Run calico/node docker-image acceptance tests
node-test-at: release-prereq
	docker run -v $(CALICO_NODE_DIR)tests/at/calico_node_goss.yaml:/tmp/goss.yaml \
	calico/node:$(VERSION) /bin/sh -c 'apk --no-cache add wget ca-certificates && \
	wget -q -O /tmp/goss \
	https://github.com/aelsabbahy/goss/releases/download/v0.3.4/goss-linux-amd64 && \
	chmod +rx /tmp/goss && \
	/tmp/goss --gossfile /tmp/goss.yaml validate'

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

###############################################################################
# Utilities 
###############################################################################
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


$(info "Build dependency versions")
$(info $(shell printf "%-21s = %-10s\n" "BIRD_VER" $(BIRD_VER)))

$(info "Test dependency versions")
$(info $(shell printf "%-21s = %-10s\n" "CNI_VER" $(CNI_VER)))
$(info $(shell printf "%-21s = %-10s\n" "RR_VER" $(RR_VER)))

$(info "Calico git version")
$(info $(shell printf "%-21s = %-10s\n" "CALICO_GIT_VER" $(CALICO_GIT_VER)))
