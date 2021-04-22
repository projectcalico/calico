PACKAGE_NAME=github.com/projectcalico/calicoctl
GO_BUILD_VER=v0.52

SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_CALICOCTL_PROJECT_ID)

KUBE_APISERVER_PORT?=8080
KUBE_MOCK_NODE_MANIFEST?=mock-node.yaml

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

EXTRA_DOCKER_ARGS+=-v $(CURDIR)/../libcalico-go:/go/src/github.com/projectcalico/libcalico-go:rw
$(LOCAL_BUILD_DEP):
	$(DOCKER_RUN) $(CALICO_BUILD) go mod edit -replace=github.com/projectcalico/libcalico-go=../libcalico-go
endif

include Makefile.common

###############################################################################

BUILD_IMAGE?=calico/ctl
PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/ctl
RELEASE_IMAGES?=

CALICOCTL_DIR=calicoctl
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created-$(ARCH)
SRC_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')

TEST_CONTAINER_NAME ?= calico/test

CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/v3/calicoctl/commands.VERSION=$(GIT_VERSION) \
	-X $(PACKAGE_NAME)/v3/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) -s -w"

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '*.created-$(ARCH)' -exec rm -f {} \;
	rm -rf .go-pkg-cache bin build certs *.tar vendor Makefile.common* calicoctl/commands/report
	docker rmi $(BUILD_IMAGE):latest-$(ARCH) || true
	docker rmi $(BUILD_IMAGE):$(VERSION)-$(ARCH) || true
ifeq ($(ARCH),amd64)
	docker rmi $(BUILD_IMAGE):latest || true
	docker rmi $(BUILD_IMAGE):$(VERSION) || true
endif

###############################################################################
# Updating pins
###############################################################################
update-pins: update-libcalico-pin

###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/calicoctl-linux-,$(VALIDARCHES)) bin/calicoctl-windows-amd64.exe bin/calicoctl-darwin-amd64
.PHONY: build
## Build the binary for the current architecture and platform
build: bin/calicoctl-$(BUILDOS)-$(ARCH)
# The supported different binary names. For each, ensure that an OS and ARCH is set
bin/calicoctl-%-amd64: ARCH=amd64
bin/calicoctl-%-armv7: ARCH=armv7
bin/calicoctl-%-arm64: ARCH=arm64
bin/calicoctl-%-ppc64le: ARCH=ppc64le
bin/calicoctl-%-s390x: ARCH=s390x
bin/calicoctl-darwin-amd64: BUILDOS=darwin
bin/calicoctl-windows-amd64: BUILDOS=windows
bin/calicoctl-linux-%: BUILDOS=linux
# We reinvoke make here to re-evaluate BUILDOS and ARCH so the correct values
# for multi-platform builds are used. When make is initially invoked, BUILDOS
# and ARCH are defined with default values (Linux and amd64).
bin/calicoctl-%: $(LOCAL_BUILD_DEP) $(SRC_FILES)
	$(MAKE) build-calicoctl BUILDOS=$(BUILDOS) ARCH=$(ARCH)
build-calicoctl:
	mkdir -p bin
	$(DOCKER_RUN) \
	  -e CALICOCTL_GIT_REVISION=$(CALICOCTL_GIT_REVISION) \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  $(CALICO_BUILD) \
	  go build -v -o bin/calicoctl-$(BUILDOS)-$(ARCH) $(LDFLAGS) "./calicoctl/calicoctl.go"
# Overrides for the binaries that need different output names
bin/calicoctl: bin/calicoctl-linux-amd64
	cp $< $@
bin/calicoctl-windows-amd64.exe: bin/calicoctl-windows-amd64
	mv $< $@

gen-crds: remote-deps
	$(DOCKER_RUN) \
	  -v $(CURDIR)/calicoctl/commands/crds:/go/src/$(PACKAGE_NAME)/calicoctl/commands/crds \
	  $(CALICO_BUILD) \
	  sh -c 'cd /go/src/$(PACKAGE_NAME)/calicoctl/commands/crds && go generate'

remote-deps: mod-download	
	$(DOCKER_RUN) $(CALICO_BUILD) sh -ec ' \
		$(GIT_CONFIG_SSH) \
		cp -r `go list -m -f "{{.Dir}}" github.com/projectcalico/libcalico-go`/config .; \
		chmod -R +w config/'

###############################################################################
# Building the image
###############################################################################
.PHONY: image $(BUILD_IMAGE)
image: $(BUILD_IMAGE)
$(BUILD_IMAGE): $(CTL_CONTAINER_CREATED)
$(CTL_CONTAINER_CREATED): Dockerfile.$(ARCH) bin/calicoctl-linux-$(ARCH)
	docker build -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --build-arg GIT_VERSION=$(GIT_VERSION) -f Dockerfile.$(ARCH) .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif
	touch $@

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

###############################################################################
# Image build/push
###############################################################################
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

imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))

sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

## push all arches
push-all: imagetag $(addprefix sub-push-,$(VALIDARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## push multi-arch manifest where supported
push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using
	# $(DOCKER_CONFIG) holds the docker login credentials path to credentials based on
	# manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
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
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev.
ut: $(LOCAL_BUILD_DEP) bin/calicoctl-linux-amd64
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -cover -r calicoctl/*'

###############################################################################
# FVs
###############################################################################
.PHONY: fv
## Run the tests in a container. Useful for CI, Mac dev.
fv: $(LOCAL_BUILD_DEP) bin/calicoctl-linux-amd64
	$(MAKE) run-etcd-host
	# We start two API servers in order to test multiple kubeconfig support
	$(MAKE) run-kubernetes-master KUBE_APISERVER_PORT=8080 KUBE_MOCK_NODE_MANIFEST=mock-node.yaml
	$(MAKE) run-kubernetes-master KUBE_APISERVER_PORT=8082 KUBE_MOCK_NODE_MANIFEST=mock-node-second.yaml
	# Run the tests
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && go test ./tests/fv'
	# Cleanup
	$(MAKE) stop-etcd
	$(MAKE) stop-kubernetes-master KUBE_APISERVER_PORT=8080
	$(MAKE) stop-kubernetes-master KUBE_APISERVER_PORT=8082

###############################################################################
# STs
###############################################################################
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')
# To run a specific test, set ST_TO_RUN to testfile.py:class.method
# e.g. ST_TO_RUN="tests/st/calicoctl/test_crud.py:TestCalicoctlCommands.test_get_delete_multiple_names"
ST_TO_RUN?=tests/st/calicoctl/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

.PHONY: st
## Run the STs in a container
st: bin/calicoctl-linux-amd64
	$(MAKE) run-etcd-host
	$(MAKE) run-kubernetes-master
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
		   sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/report/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd
	$(MAKE) stop-kubernetes-master

## Etcd is used by the STs
# NOTE: https://quay.io/repository/coreos/etcd is available *only* for the following archs with the following tags:
# amd64: 3.3.7
# arm64: 3.3.7-arm64
# ppc64le: 3.3.7-ppc64le
# s390x is not available
# armv7 is not available
COREOS_ETCD?=quay.io/coreos/etcd:$(ETCD_VERSION)-$(ARCH)
ifeq ($(ARCH),amd64)
COREOS_ETCD=quay.io/coreos/etcd:$(ETCD_VERSION)
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

## Run a local kubernetes master with API via hyperkube
run-kubernetes-master: stop-kubernetes-master
	# Run a Kubernetes apiserver using Docker.
	docker run \
		--net=host --name st-apiserver-${KUBE_APISERVER_PORT} \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} kube-apiserver \
			--bind-address=0.0.0.0 \
			--secure-port=1${KUBE_APISERVER_PORT} \
			--insecure-bind-address=0.0.0.0 \
			--port=${KUBE_APISERVER_PORT} \
	        	--etcd-servers=http://127.0.0.1:2379 \
			--admission-control=NamespaceLifecycle,LimitRanger,DefaultStorageClass,ResourceQuota \
			--service-cluster-ip-range=10.101.0.0/16 \
			--v=10 \
			--logtostderr=true

	# Wait until the apiserver is accepting requests.
	while ! docker exec st-apiserver-${KUBE_APISERVER_PORT} kubectl get nodes; do echo "Waiting for apiserver to come up..."; sleep 2; done

	# And run the controller manager.
	docker run \
		--net=host --name st-controller-manager-${KUBE_APISERVER_PORT} \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} kube-controller-manager \
                        --master=127.0.0.1:${KUBE_APISERVER_PORT} \
                        --min-resync-period=3m \
                        --allocate-node-cidrs=true \
                        --cluster-cidr=10.10.0.0/16 \
                        --v=5

	# Create a Node in the API for the tests to use.
	while ! docker run \
	    --net=host \
	    --rm \
		-v $(CURDIR):/manifests \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} kubectl \
		--server=http://127.0.0.1:${KUBE_APISERVER_PORT} \
		apply -f /manifests/tests/st/manifests/${KUBE_MOCK_NODE_MANIFEST}; \
		do echo "Waiting for node to apply successfully..."; sleep 2; done

	# Create a namespace in the API for the tests to use.
	-docker run \
	    --net=host \
	    --rm \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} kubectl \
		--server=http://127.0.0.1:${KUBE_APISERVER_PORT} \
		create namespace test
	
## Stop the local kubernetes master
stop-kubernetes-master:
	# Delete the cluster role binding.
	-docker exec st-apiserver-${KUBE_APISERVER_PORT} kubectl delete clusterrolebinding anonymous-admin

	# Stop master components.
	-docker rm -f st-apiserver-${KUBE_APISERVER_PORT} st-controller-manager-${KUBE_APISERVER_PORT}

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: mod-download build-all static-checks test

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
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long --abbrev=12) EXCLUDEARCH="$(EXCLUDEARCH)"

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
	$(MAKE) build-all image-all
	$(MAKE) tag-images-all IMAGETAG=$(VERSION)
	$(MAKE) tag-images-all IMAGETAG=latest

	# Copy the amd64 variant to calicoctl - for now various downstream projects
	# expect this naming convention. Until they can be swapped over, we still need to
	# publish a binary called calicoctl.
	$(MAKE) bin/calicoctl

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(BUILD_IMAGE):$(VERSION)-$(ARCH) version` "\nExpected version: $(VERSION)"; \
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

	# Push binaries to GitHub release.
	# Requires ghr: https://github.com/tcnksm/ghr
	# Requires GITHUB_TOKEN environment variable set.
	ghr -u projectcalico -r calicoctl \
		-b "Release notes can be found at https://docs.projectcalico.org" \
		-n $(VERSION) \
		$(VERSION) ./bin/

	@echo "Confirm that the release was published at the following URL."
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
	if ! docker run $(BUILD_IMAGE):latest-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(BUILD_IMAGE):latest-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set for a release)
endif
ifeq (, $(shell which ghr))
	$(error Unable to find `ghr` in PATH, run this: go get -u github.com/tcnksm/ghr)
endif
