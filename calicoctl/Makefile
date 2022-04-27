include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/calicoctl

KUBE_APISERVER_PORT?=6443
KUBE_MOCK_NODE_MANIFEST?=mock-node.yaml

# Name of the images.
# e.g., <registry>/<name>:<tag>
CALICOCTL_IMAGE       ?=ctl
BUILD_IMAGES          ?=$(CALICOCTL_IMAGE)
RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

# Remove any excluded architectures since for calicoctl we want to build everything.
EXCLUDEARCH?=

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################

CALICOCTL_DIR=calicoctl
CTL_CONTAINER_CREATED=$(CALICOCTL_DIR)/.calico_ctl.created-$(ARCH)
SRC_FILES=$(shell find $(CALICOCTL_DIR) -name '*.go')

TEST_CONTAINER_NAME ?= calico/test

CALICOCTL_GIT_REVISION?=$(shell git rev-parse --short HEAD)

LDFLAGS=-ldflags "-X $(PACKAGE_NAME)/calicoctl/commands.VERSION=$(GIT_VERSION) \
	-X $(PACKAGE_NAME)/calicoctl/commands.GIT_REVISION=$(CALICOCTL_GIT_REVISION) \
	-X $(PACKAGE_NAME)/calicoctl/commands/common.VERSION=$(GIT_VERSION)"

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf .go-pkg-cache bin build certs *.tar calicoctl/commands/report $(CALICO_VERSION_HELPER_DIR)/bin
	docker rmi $(CALICOCTL_IMAGE):latest-$(ARCH) || true
	docker rmi $(CALICOCTL_IMAGE):$(VERSION)-$(ARCH) || true
ifeq ($(ARCH),amd64)
	docker rmi $(CALICOCTL_IMAGE):latest || true
	docker rmi $(CALICOCTL_IMAGE):$(VERSION) || true
endif

###############################################################################
# Building the binary
###############################################################################
.PHONY: build-all
## Build the binaries for all architectures and platforms
build-all: $(addprefix bin/calicoctl-linux-,$(VALIDARCHES)) bin/calicoctl-windows-amd64.exe bin/calicoctl-darwin-amd64 bin/calicoctl-darwin-arm64
.PHONY: build
## Build the binary for the current architecture and platform
build: bin/calicoctl-$(BUILDOS)-$(ARCH)
# The supported different binary names. For each, ensure that an OS and ARCH is set
bin/calicoctl-%-amd64: ARCH=amd64
bin/calicoctl-%-armv7: ARCH=armv7
bin/calicoctl-%-arm64: ARCH=arm64
bin/calicoctl-%-ppc64le: ARCH=ppc64le
bin/calicoctl-%-s390x: ARCH=s390x
bin/calicoctl-darwin-amd64: BUILDOS=darwin ARCH=amd64
bin/calicoctl-darwin-arm64: BUILDOS=darwin ARCH=arm64
bin/calicoctl-windows-amd64: BUILDOS=windows
bin/calicoctl-linux-%: BUILDOS=linux
# We reinvoke make here to re-evaluate BUILDOS and ARCH so the correct values
# for multi-platform builds are used. When make is initially invoked, BUILDOS
# and ARCH are defined with default values (Linux and amd64).
bin/calicoctl-%: $(SRC_FILES)
	$(MAKE) build-calicoctl BUILDOS=$(BUILDOS) ARCH=$(ARCH)
build-calicoctl:
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) \
	  go build -v -o bin/calicoctl-$(BUILDOS)-$(ARCH) $(LDFLAGS) "./calicoctl/calicoctl.go"

# Overrides for the binaries that need different output names
bin/calicoctl: bin/calicoctl-linux-amd64
	cp $< $@
bin/calicoctl-windows-amd64.exe: bin/calicoctl-windows-amd64
	mv $< $@

gen-crds:
	$(DOCKER_RUN) \
	  $(CALICO_BUILD) \
	  sh -c 'cd /go/src/$(PACKAGE_NAME)/calicoctl/commands/crds && go generate'

###############################################################################
# Building the image
###############################################################################
.PHONY: image $(CALICOCTL_IMAGE)
image: $(CALICOCTL_IMAGE)
$(CALICOCTL_IMAGE): $(CTL_CONTAINER_CREATED)
$(CTL_CONTAINER_CREATED): Dockerfile.$(ARCH) bin/calicoctl-linux-$(ARCH) register
	$(DOCKER_BUILD) -t $(CALICOCTL_IMAGE):latest-$(ARCH) -f Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

CALICO_VERSION_HELPER_DIR=tests/fv/helper
CALICO_VERSION_HELPER_BIN=$(CALICO_VERSION_HELPER_DIR)/bin/calico_version_helper
CALICO_VERSION_HELPER_SRC=$(CALICO_VERSION_HELPER_DIR)/calico_version_helper.go

.PHONY: version-helper
version-helper: $(CALICO_VERSION_HELPER_BIN)
$(CALICO_VERSION_HELPER_BIN): $(CALICO_VERSION_HELPER_SRC)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && \
		go build -v -o $(CALICO_VERSION_HELPER_BIN) -ldflags "-X main.VERSION=$(GIT_VERSION)" $(CALICO_VERSION_HELPER_SRC)'

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev.
ut: bin/calicoctl-linux-amd64
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo2 -cover -r calicoctl/*'

###############################################################################
# FVs
###############################################################################
.PHONY: fv
## Run the tests in a container. Useful for CI, Mac dev.
fv: bin/calicoctl-linux-amd64 version-helper
	$(MAKE) run-etcd

	# We start two API servers in order to test multiple kubeconfig support
	$(MAKE) run-kubernetes-master KUBE_APISERVER_PORT=6443 KUBE_MOCK_NODE_MANIFEST=mock-node.yaml
	$(MAKE) run-kubernetes-master KUBE_APISERVER_PORT=6444 KUBE_MOCK_NODE_MANIFEST=mock-node-second.yaml

	# Ensure anonymous is permitted to be admin.
	while ! docker exec st-apiserver-6443 kubectl --server=https://127.0.0.1:6443 create clusterrolebinding anonymous-admin --clusterrole=cluster-admin --user=system:anonymous; do sleep 2; done

	# Run the tests
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && go test ./tests/fv'
	# Cleanup
	$(MAKE) stop-etcd
	$(MAKE) stop-kubernetes-master KUBE_APISERVER_PORT=6443
	$(MAKE) stop-kubernetes-master KUBE_APISERVER_PORT=6444

###############################################################################
# STs
###############################################################################
# To run a specific test, set ST_TO_RUN to testfile.py:class.method
# e.g. ST_TO_RUN="tests/st/calicoctl/test_crud.py:TestCalicoctlCommands.test_get_delete_multiple_names"
ST_TO_RUN?=tests/st/calicoctl/
# Can exclude the slower tests with "-a '!slow'"
ST_OPTIONS?=

.PHONY: st
## Run the STs in a container
st: bin/calicoctl-linux-amd64 version-helper
	$(MAKE) run-etcd
	$(MAKE) run-kubernetes-master
	# Use the host, PID and network namespaces from the host.
	# Privileged is needed since 'calico node' write to /proc (to enable ip_forwarding)
	# Map the docker socket in so docker can be used from inside the container
	# All of code under test is mounted into the container.
	#   - This also provides access to calicoctl and the docker client
	docker run --net=host --privileged \
		   -e MY_IP=$(LOCAL_IP_ENV) \
		   --rm -t \
		   -v $(CERTS_PATH):/home/user/certs \
		   -v $(CURDIR):/code \
		   -v /var/run/docker.sock:/var/run/docker.sock \
		   $(TEST_CONTAINER_NAME) \
		   sh -c 'nosetests $(ST_TO_RUN) -sv --nologcapture  --with-xunit --xunit-file="/code/report/nosetests.xml" --with-timer $(ST_OPTIONS)'
	$(MAKE) stop-etcd
	$(MAKE) stop-kubernetes-master

## Run a local kubernetes master with API
# TODO: Commonize this with the functions in lib.Makefile. 
# For now, these tests do something special and launch two apiserver on different ports, so it makes sense
# to keep them separate.
run-kubernetes-master: stop-kubernetes-master
	# Run a Kubernetes apiserver using Docker.
	docker run --net=host --detach \
		--name st-apiserver-${KUBE_APISERVER_PORT} \
		-v $(CURDIR):/code \
		-v $(CURDIR)/../:/go/src/github.com/projectcalico/calico \
		-v $(CERTS_PATH):/home/user/certs \
		-e KUBECONFIG=/home/user/certs/kubeconfig \
		${CALICO_BUILD} kube-apiserver \
			--secure-port=${KUBE_APISERVER_PORT} \
			--admission-control=NamespaceLifecycle,LimitRanger,DefaultStorageClass,ResourceQuota \
			--etcd-servers=http://$(LOCAL_IP_ENV):2379 \
                        --service-cluster-ip-range=10.101.0.0/16 \
                        --authorization-mode=RBAC \
                        --service-account-key-file=/home/user/certs/service-account.pem \
                        --service-account-signing-key-file=/home/user/certs/service-account-key.pem \
                        --service-account-issuer=https://localhost:443 \
                        --api-audiences=kubernetes.default \
                        --client-ca-file=/home/user/certs/ca.pem \
                        --tls-cert-file=/home/user/certs/kubernetes.pem \
                        --tls-private-key-file=/home/user/certs/kubernetes-key.pem \
                        --enable-priority-and-fairness=false \
                        --max-mutating-requests-inflight=0 \
                        --max-requests-inflight=0


	# Wait until the apiserver is accepting requests.
	while ! docker exec st-apiserver-${KUBE_APISERVER_PORT} kubectl --server=https://127.0.0.1:${KUBE_APISERVER_PORT} get nodes; do echo "Waiting for apiserver to come up..."; sleep 2; done

	# And run the controller manager.
	docker run --detach --net=host \
	  --name st-controller-manager-${KUBE_APISERVER_PORT} \
	  -v $(CERTS_PATH):/home/user/certs \
	  $(CALICO_BUILD) kube-controller-manager \
	    --master=https://127.0.0.1:${KUBE_APISERVER_PORT} \
            --kubeconfig=/home/user/certs/kube-controller-manager.kubeconfig \
            --min-resync-period=3m \
            --allocate-node-cidrs=true \
            --cluster-cidr=10.10.0.0/16 \
            --v=5 \
            --service-account-private-key-file=/home/user/certs/service-account-key.pem \
            --root-ca-file=/home/user/certs/ca.pem

	# Create a Node in the API for the tests to use.
	while ! docker exec -ti st-apiserver-${KUBE_APISERVER_PORT} kubectl \
		--server=https://127.0.0.1:${KUBE_APISERVER_PORT} \
		apply -f /code/tests/st/manifests/${KUBE_MOCK_NODE_MANIFEST}; \
		do echo "Waiting for node to apply successfully..."; sleep 2; done

	# Apply CRDs because the tests require them.
	while ! docker exec -ti st-apiserver-${KUBE_APISERVER_PORT} kubectl \
		--server=https://127.0.0.1:${KUBE_APISERVER_PORT} \
		apply -f /go/src/github.com/projectcalico/calico/libcalico-go/config/crd; \
		do echo "Waiting for ClusterInformation CRD to apply successfully..."; sleep 2; done

	# Create a namespace in the API for the tests to use.
	-docker exec -ti st-apiserver-${KUBE_APISERVER_PORT} kubectl \
		--server=https://127.0.0.1:${KUBE_APISERVER_PORT} \
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
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created 
.release-$(VERSION).created:
	$(MAKE) clean build-all image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(CALICOCTL_IMAGE):$(VERSION)-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(CALICOCTL_IMAGE):$(VERSION)-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(CALICOCTL_IMAGE):latest-$(ARCH) version | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run $(CALICOCTL_IMAGE):latest-$(ARCH) version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
