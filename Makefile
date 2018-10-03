# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: fv st

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

# Build mounts for running in "local build" mode. Mount in libcalico, confd, and felix but null out
# their respective vendor directories. This allows an easy build of calico/node using local development code,
# assuming that there is a local checkout of felix, confd, and libcalico in the same directory as the node repo.
LOCAL_BUILD_MOUNTS ?=
ifeq ($(LOCAL_BUILD),true)
LOCAL_BUILD_MOUNTS = -v $(CURDIR)/../libcalico-go:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go:ro \
	-v $(CURDIR)/.empty:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go/vendor:ro \
	-v $(CURDIR)/../confd:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/confd:ro \
	-v $(CURDIR)/.empty:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/confd/vendor:ro \
	-v $(CURDIR)/../felix:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/felix:ro \
	-v $(CURDIR)/.empty:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/felix/vendor:ro
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

# Targets used when cross building.
.PHONY: register
# Enable binfmt adding support for miscellaneous binary formats.
# This is only needed when running non-native binaries.
register:
ifneq ($(BUILDARCH),$(ARCH))
	docker run --rm --privileged multiarch/qemu-user-static:register || true
endif

# list of arches *not* to build when doing *-all
#    until s390x works correctly
EXCLUDEARCH ?= s390x
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

###############################################################################
BUILD_IMAGE?=calico/node
PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/node
RELEASE_IMAGES?=gcr.io/projectcalico-org/node eu.gcr.io/projectcalico-org/node asia.gcr.io/projectcalico-org/node us.gcr.io/projectcalico-org/node

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGES+=$(RELEASE_IMAGES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES ?= quay.io/
PUSH_MANIFEST_IMAGES=$(PUSH_IMAGES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGES=$(filter-out $(PUSH_MANIFEST_IMAGES),$(PUSH_IMAGES))

GO_BUILD_VER?=v0.17
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

# Version of this repository as reported by git.
CALICO_GIT_VER := $(shell git describe --tags --dirty --always)
ifeq ($(LOCAL_BUILD),true)
	CALICO_GIT_VER = $(shell git describe --tags --dirty --always)-dev-build
endif

# Versions and location of dependencies used in the build.
BIRD_VER?=v0.3.2-13-g17d14e60
BIRD_IMAGE ?= calico/bird:$(BIRD_VER)-$(ARCH)

# Versions and locations of dependencies used in tests.
CALICOCTL_VER?=master
CNI_VER?=master
TEST_CONTAINER_NAME_VER?=latest
CTL_CONTAINER_NAME?=calico/ctl:$(CALICOCTL_VER)-$(ARCH)
TEST_CONTAINER_NAME?=calico/test:$(TEST_CONTAINER_NAME_VER)-$(ARCH)
ETCD_VERSION?=v3.3.7
# If building on amd64 omit the arch in the container name.  Fixme!
ETCD_IMAGE?=quay.io/coreos/etcd:$(ETCD_VERSION)
ifneq ($(BUILDARCH),amd64)
        ETCD_IMAGE=$(ETCD_IMAGE)-$(ARCH)
endif

K8S_VERSION?=v1.11.3
HYPERKUBE_IMAGE?=gcr.io/google_containers/hyperkube-$(ARCH):$(K8S_VERSION)
TEST_CONTAINER_FILES=$(shell find tests/ -type f ! -name '*.created')

# Variables controlling the image
NODE_CONTAINER_CREATED=.calico_node.created-$(ARCH)
NODE_CONTAINER_BIN_DIR=./dist/bin/
NODE_CONTAINER_BINARY = $(NODE_CONTAINER_BIN_DIR)/calico-node-$(ARCH)

# Variables used by the tests
CRD_PATH=$(CURDIR)/vendor/github.com/projectcalico/libcalico-go/test/
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
ST_TO_RUN?=tests/st/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

# Variables for building the local binaries that go into the image
MAKE_SURE_BIN_EXIST := $(shell mkdir -p dist .go-pkg-cache $(NODE_CONTAINER_BIN_DIR))
NODE_CONTAINER_FILES=$(shell find ./filesystem -type f)
SRCFILES=$(shell find ./pkg -name '*.go')
LOCAL_USER_ID?=$(shell id -u $$USER)

LDFLAGS=-ldflags "-X github.com/projectcalico/node/pkg/startup.VERSION=$(CALICO_GIT_VER) \
                  -X github.com/projectcalico/node/vendor/github.com/projectcalico/felix/buildinfo.GitVersion=$(CALICO_GIT_VER) \
                  -X github.com/projectcalico/node/vendor/github.com/projectcalico/felix/buildinfo.GitRevision=$(shell git rev-parse HEAD || echo '<unknown>')"

PACKAGE_NAME?=github.com/projectcalico/node
LIBCALICOGO_PATH?=none

## Clean enough that a new release build will be clean
clean:
	find . -name '*.created' -exec rm -f {} +
	find . -name '*.pyc' -exec rm -f {} +
	rm -rf certs *.tar vendor $(NODE_CONTAINER_BIN_DIR)

	# Delete images that we built in this repo
	docker rmi $(BUILD_IMAGE):latest-$(ARCH) || true
	docker rmi $(TEST_CONTAINER_NAME) || true

###############################################################################
# Building the binary
###############################################################################
build:  $(NODE_CONTAINER_BINARY)
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
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) glide install -strip-vendor

## Default the repos and versions but allow them to be overridden
LIBCALICO_REPO?=github.com/projectcalico/libcalico-go
LIBCALICO_VERSION?=$(shell git ls-remote git@github.com:projectcalico/libcalico-go master 2>/dev/null | cut -f 1)
FELIX_REPO?=github.com/projectcalico/felix
FELIX_VERSION?=$(shell git ls-remote git@github.com:projectcalico/felix master 2>/dev/null | cut -f 1)
CONFD_REPO?=github.com/projectcalico/confd
CONFD_VERSION?=$(shell git ls-remote git@github.com:projectcalico/confd master 2>/dev/null | cut -f 1)

### Update pins in glide.yaml
update-felix-confd-libcalico:
	docker run --rm \
        -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw $$EXTRA_DOCKER_BIND \
        -v $(HOME)/.glide:/home/user/.glide:rw \
        -w /go/src/$(PACKAGE_NAME) \
        -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
        $(CALICO_BUILD) sh -c '\
          echo "Updating libcalico to $(LIBCALICO_VERSION) from $(LIBCALICO_REPO)"; \
          echo "Updating felix to $(FELIX_VERSION) from $(FELIX_REPO)"; \
          echo "Updating confd to $(CONFD_VERSION) from $(CONFD_REPO)"; \
          export OLD_LIBCALICO_VER=$$(grep --after 50 libcalico glide.yaml |grep --max-count=1 --only-matching --perl-regexp "version:\s*\K[\.0-9a-z]+") ;\
          export OLD_FELIX_VER=$$(grep --after 50 felix glide.yaml |grep --max-count=1 --only-matching --perl-regexp "version:\s*\K[\.0-9a-z]+") ;\
          export OLD_CONFD_VER=$$(grep --after 50 confd glide.yaml |grep --max-count=1 --only-matching --perl-regexp "version:\s*\K[\.0-9a-z]+") ;\
          echo "Old libcalico version: $$OLD_LIBCALICO_VER";\
          echo "Old felix version: $$OLD_FELIX_VER";\
          echo "Old confd version: $$OLD_CONFD_VER";\
          if [ $(LIBCALICO_VERSION) != $$OLD_LIBCALICO_VER ] || [ $(FELIX_VERSION) != $$OLD_FELIX_VER ] || [ $(CONFD_VERSION) != $$OLD_CONFD_VER ]; then \
            sed -i "s/$$OLD_LIBCALICO_VER/$(LIBCALICO_VERSION)/" glide.yaml && \
            sed -i "s/$$OLD_FELIX_VER/$(FELIX_VERSION)/" glide.yaml && \
            sed -i "s/$$OLD_CONFD_VER/$(CONFD_VERSION)/" glide.yaml && \
            OUTPUT=`mktemp`;\
            glide up --strip-vendor; glide up --strip-vendor 2>&1 | tee $$OUTPUT; \
            if ! grep "\[WARN\]" $$OUTPUT; then true; else false; fi; \
          fi'

$(NODE_CONTAINER_BINARY): vendor
	docker run --rm \
		-e GOARCH=$(ARCH) \
		-e GOOS=linux \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
		-e GOCACHE=/go-cache \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		$(LOCAL_BUILD_MOUNTS) \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) go build -v -o $@ $(LDFLAGS) ./cmd/calico-node/main.go

###############################################################################
# Building the image
###############################################################################
## Create the image for the current ARCH
image: $(BUILD_IMAGE)
## Create the images for all supported ARCHes
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

$(BUILD_IMAGE): $(NODE_CONTAINER_CREATED)
$(NODE_CONTAINER_CREATED): register ./Dockerfile.$(ARCH) $(NODE_CONTAINER_FILES) $(NODE_CONTAINER_BINARY)
	# Check versions of the binaries that we're going to use to build the image.
	# Since the binaries are built for Linux, run them in a container to allow the
	# make target to be run on different platforms (e.g. MacOS).
	docker run --rm -v $(CURDIR)/dist/bin:/go/bin:rw $(CALICO_BUILD) /bin/sh -c "\
	  echo; echo calico-node-$(ARCH) -v;         /go/bin/calico-node-$(ARCH) -v; \
	"
	docker build --pull -t $(BUILD_IMAGE):latest-$(ARCH) . --build-arg BIRD_IMAGE=$(BIRD_IMAGE) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --build-arg ver=$(CALICO_GIT_VER) -f ./Dockerfile.$(ARCH)
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

## push all supported arches
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

## tag images of one arch for all supported registries
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
.PHONY: static-checks
## Perform static checks on the code.
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME) \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) gometalinter --deadline=300s --disable-all --enable=vet --enable=errcheck --enable=goimports --vendor pkg/...

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
	$(LOCAL_BUILD_MOUNTS) \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	--net=host \
	-w /go/src/$(PACKAGE_NAME) \
	$(CALICO_BUILD) ginkgo -cover -r -skipPackage vendor pkg/startup pkg/allocateipip $(GINKGO_ARGS)

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

workload.tar:
	cd workload && docker build -t workload --build-arg QEMU_IMAGE=$(CALICO_BUILD) -f Dockerfile.$(ARCH) .
	docker save --output workload.tar workload

stop-etcd:
	@-docker rm -f calico-etcd

IPT_ALLOW_ETCD:=-A INPUT -i docker0 -p tcp --dport 2379 -m comment --comment "calico-st-allow-etcd" -j ACCEPT

# Create the calico/test image
test_image: calico_test.created
calico_test.created: $(TEST_CONTAINER_FILES)
	cd calico_test && docker build --build-arg QEMU_IMAGE=$(CALICO_BUILD) -f Dockerfile.$(ARCH).calico_test -t $(TEST_CONTAINER_NAME) .
	touch calico_test.created

calico-node.tar: $(NODE_CONTAINER_CREATED)
	# Check versions of the Calico binaries that will be in calico-node.tar.
	# Since the binaries are built for Linux, run them in a container to allow the
	# make target to be run on different platforms (e.g. MacOS).
	docker run --rm $(BUILD_IMAGE):latest-$(ARCH) /bin/sh -c "\
	  echo bird --version;         /bin/bird --version; \
	"
	docker save --output $@ $(BUILD_IMAGE):latest-$(ARCH)

.PHONY: st-checks
st-checks:
	# Check that we're running as root.
	test `id -u` -eq '0' || { echo "STs must be run as root to allow writes to /proc"; false; }

	# Insert an iptables rule to allow access from our test containers to etcd
	# running on the host.
	iptables-save | grep -q 'calico-st-allow-etcd' || iptables $(IPT_ALLOW_ETCD)

.PHONY: st
## Run the system tests
st: dist/calicoctl busybox.tar calico-node.tar workload.tar run-etcd calico_test.created dist/calico-cni-plugin dist/calico-ipam-plugin
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
	           -e NODE_CONTAINER_NAME=$(BUILD_IMAGE):latest-$(ARCH) \
	           --rm -t \
	           -v /var/run/docker.sock:/var/run/docker.sock \
	           $(TEST_CONTAINER_NAME) \
	           sh -c 'nosetests $(ST_TO_RUN) -v --with-xunit --xunit-file="/code/report/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: static-checks fv image-all st

## Deploys images to registry
cd:
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
	$(MAKE) image-all
	$(MAKE) tag-images-all RELEASE=true IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images-all RELEASE=true IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) versions | grep 'node $(VERSION)'; then echo "Reported version:" `docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) versions` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

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
	$(MAKE) push-all push-manifests push-non-manifests RELEASE=true IMAGETAG=$(VERSION)

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
release-publish-latest: release-verify
	$(MAKE) push-all push-manifests push-non-manifests RELEASE=true IMAGETAG=latest

.PHONY: node-test-at
# Run docker-image acceptance tests
node-test-at: release-prereqs
	docker run -v $(PWD)/tests/at/calico_node_goss.yaml:/tmp/goss.yaml \
	  $(BUILD_IMAGE):$(VERSION) /bin/sh -c ' \
	   apk --no-cache add wget ca-certificates && \
	   wget -q -O /tmp/goss https://github.com/aelsabbahy/goss/releases/download/v0.3.4/goss-linux-amd64 && \
	   chmod +rx /tmp/goss && \
	   /tmp/goss --gossfile /tmp/goss.yaml validate'

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
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

$(info "Calico git version")
$(info $(shell printf "%-21s = %-10s\n" "CALICO_GIT_VER" $(CALICO_GIT_VER)))
