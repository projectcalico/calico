PACKAGE_NAME=github.com/kelseyhightower/confd
GO_BUILD_VER=v0.51

ORGANIZATION=projectcalico
SEMAPHORE_PROJECT_ID=$(SEMAPHORE_CONFD_PROJECT_ID)

# Used so semaphore can trigger the update pin pipelines in projects that have this project as a dependency.
SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS=$(SEMAPHORE_NODE_PROJECT_ID)

###############################################################################
# Download and include Makefile.common
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

# Build mounts for running in "local build" mode. This allows an easy build using local development code,
# assuming that there is a local checkout of libcalico in the same directory as this repo.
ifdef LOCAL_BUILD
PHONY: set-up-local-build
LOCAL_BUILD_DEP:=set-up-local-build

EXTRA_DOCKER_ARGS+=-v $(CURDIR)/../libcalico-go:/go/src/github.com/projectcalico/libcalico-go:rw \
	-v $(CURDIR)/../typha:/go/src/github.com/projectcalico/typha:rw
$(LOCAL_BUILD_DEP):
	$(DOCKER_RUN) $(CALICO_BUILD) go mod edit -replace=github.com/projectcalico/libcalico-go=../libcalico-go \
		-replace=github.com/projectcalico/typha=../typha
endif

include Makefile.common

# Override K8S_VERSION
K8S_VERSION=v1.17.0

###############################################################################

test: ut test-kdd test-etcd

CALICOCTL_VER=master
CALICOCTL_CONTAINER_NAME=calico/ctl:$(CALICOCTL_VER)-$(ARCH)
TYPHA_VER=master
TYPHA_CONTAINER_NAME=calico/typha:$(TYPHA_VER)-$(ARCH)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/pkg/buildinfo.GitVersion=$(GIT_DESCRIPTION)"

# All go files.
SRC_FILES:=$(shell find . -name '*.go' -not -path "./vendor/*" )

.PHONY: clean
clean:
	rm -rf vendor
	rm -rf bin/*
	rm -rf tests/logs
	rm Makefile.common*

###############################################################################
# Updating pins
###############################################################################
update-pins: update-libcalico-pin update-typha-pin

###############################################################################
# Building the binary
###############################################################################
build: $(LOCAL_BUILD_DEP) bin/confd
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

bin/confd-$(ARCH): $(SRC_FILES)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'go build -v -i -o $@ $(LDFLAGS) "$(PACKAGE_NAME)" && \
		( ldd bin/confd-$(ARCH) 2>&1 | grep -q -e "Not a valid dynamic program" \
			-e "not a dynamic executable" || \
		     ( echo "Error: bin/confd was not statically linked"; false ) )'

bin/confd: bin/confd-$(ARCH)
ifeq ($(ARCH),amd64)
	ln -f bin/confd-$(ARCH) bin/confd
endif

###############################################################################
# Unit Tests
###############################################################################
# Set to true when calling test-xxx to update the rendered templates instead of
# checking them.
UPDATE_EXPECTED_DATA?=false

.PHONY: test-kdd
## Run template tests against KDD
test-kdd: bin/confd bin/kubectl bin/bird bin/bird6 bin/calico-node bin/calicoctl bin/typha run-k8s-apiserver
	-git clean -fx etc/calico/confd
	mkdir -p tests/logs
	docker run --rm --net=host \
		-v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-v $(CURDIR)/etc/calico:/etc/calico/ \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-e GOPATH=/go \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e FELIX_TYPHAADDR=127.0.0.1:5473 \
		-e FELIX_TYPHAREADTIMEOUT=50 \
		-e UPDATE_EXPECTED_DATA=$(UPDATE_EXPECTED_DATA) \
		-e GO111MODULE=on \
		-w /go/src/$(PACKAGE_NAME) \
		$(CALICO_BUILD) /tests/test_suite_kdd.sh || \
	{ \
	    echo; \
	    echo === confd single-shot log:; \
	    cat tests/logs/kdd/logss || true; \
	    echo; \
	    echo === confd daemon log:; \
	    cat tests/logs/kdd/logd1 || true; \
	    echo; \
	    echo === Typha log:; \
	    cat tests/logs/kdd/typha || true; \
	    echo; \
	    false; \
	}
	-git clean -fx etc/calico/confd

.PHONY: test-etcd
## Run template tests against etcd
test-etcd: bin/confd bin/etcdctl bin/bird bin/bird6 bin/calico-node bin/kubectl bin/calicoctl run-etcd run-k8s-apiserver
	-git clean -fx etc/calico/confd
	mkdir -p tests/logs
	docker run --rm --net=host \
		-v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-v $(CURDIR)/etc/calico:/etc/calico/ \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-e GOPATH=/go \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e UPDATE_EXPECTED_DATA=$(UPDATE_EXPECTED_DATA) \
		-e GO111MODULE=on \
		$(CALICO_BUILD) /tests/test_suite_etcd.sh
	-git clean -fx etc/calico/confd

.PHONY: ut
## Run the fast set of unit tests in a container.
ut: $(LOCAL_BUILD_DEP)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r .'

## Etcd is used by the kubernetes
# NOTE: https://quay.io/repository/coreos/etcd is available *only* for the following archs with the following tags:
# amd64: 3.2.5
# arm64: 3.2.5-arm64
# ppc64le: 3.2.5-ppc64le
# s390x is not available
COREOS_ETCD ?= quay.io/coreos/etcd:$(ETCD_VERSION)-$(ARCH)
ifeq ($(ARCH),amd64)
COREOS_ETCD = quay.io/coreos/etcd:$(ETCD_VERSION)
endif
run-etcd: stop-etcd
	docker run --detach \
	-e GO111MODULE=on \
	--net=host \
	--name calico-etcd $(COREOS_ETCD) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Stops calico-etcd containers
stop-etcd:
	@-docker rm -f calico-etcd

## Kubernetes apiserver used for tests
run-k8s-apiserver: stop-k8s-apiserver run-etcd
	docker run --detach --net=host \
	  --name calico-k8s-apiserver \
	gcr.io/google_containers/hyperkube-$(ARCH):$(K8S_VERSION) \
		  kube-apiserver --etcd-servers=http://$(LOCAL_IP_ENV):2379 \
		  --feature-gates IPv6DualStack=true \
		  --service-cluster-ip-range=10.101.0.0/16,fd00:96::/112
	# Wait until the apiserver is accepting requests.
	while ! docker exec calico-k8s-apiserver kubectl get nodes; do echo "Waiting for apiserver to come up..."; sleep 2; done

## Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f calico-k8s-apiserver

bin/kubectl:
	curl -sSf -L --retry 5 https://storage.googleapis.com/kubernetes-release/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

bin/bird:
	curl -sSf -L --retry 5 https://github.com/projectcalico/bird/releases/download/$(BIRD_VERSION)/bird -o $@
	chmod +x $@

bin/bird6:
	curl -sSf -L --retry 5 https://github.com/projectcalico/bird/releases/download/$(BIRD_VERSION)/bird6 -o $@
	chmod +x $@

bin/calico-node:
	cp fakebinary $@
	chmod +x $@

bin/etcdctl:
	curl -sSf -L --retry 5  https://github.com/coreos/etcd/releases/download/$(ETCD_VERSION)/etcd-$(ETCD_VERSION)-linux-$(ARCH).tar.gz | tar -xz -C bin --strip-components=1 etcd-$(ETCD_VERSION)-linux-$(ARCH)/etcdctl

bin/calicoctl:
	-docker rm -f calico-ctl
	# Latest calicoctl binaries are stored in automated builds of calico/ctl.
	# To get them, we create (but don't start) a container from that image.
	docker pull $(CALICOCTL_CONTAINER_NAME)
	docker create --name calico-ctl $(CALICOCTL_CONTAINER_NAME)
	# Then we copy the files out of the container.  Since docker preserves
	# mtimes on its copy, check the file really did appear, then touch it
	# to make sure that downstream targets get rebuilt.
	docker cp calico-ctl:/calicoctl $@ && \
	  test -e $@ && \
	  touch $@
	-docker rm -f calico-ctl

bin/typha:
	-docker rm -f confd-typha
	docker pull $(TYPHA_CONTAINER_NAME)
	docker create --name confd-typha $(TYPHA_CONTAINER_NAME)
	# Then we copy the files out of the container.  Since docker preserves
	# mtimes on its copy, check the file really did appear, then touch it
	# to make sure that downstream targets get rebuilt.
	docker cp confd-typha:/code/calico-typha $@ && \
	  test -e $@ && \
	  touch $@
	-docker rm -f confd-typha

fv st:
	@echo "No FVs or STs available."

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download static-checks test

###############################################################################
# Release
###############################################################################
PREVIOUS_RELEASE=$(shell git describe --tags --abbrev=0)
GIT_VERSION?=$(shell git describe --tags --dirty)

## Tags and builds a release from start to finish.
release: release-prereqs
	$(MAKE) VERSION=$(VERSION) release-tag

## Produces a git tag for the release.
release-tag: release-prereqs release-notes
	git tag $(VERSION) -F release-notes-$(VERSION)
	@echo ""
	@echo "Now you can publish the release:"
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish"
	@echo ""

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	@echo "Finalize the GitHub release based on the pushed tag."
	@echo ""
	@echo "  https://github.com/projectcalico/confd/releases/tag/$(VERSION)"
	@echo ""

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
