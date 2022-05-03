PACKAGE_NAME = github.com/projectcalico/calico

include metadata.mk 
include lib.Makefile

DOCKER_RUN := mkdir -p ./.go-pkg-cache bin $(GOMOD_CACHE) && \
	docker run --rm \
		--net=host \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e GOFLAGS=$(GOFLAGS) \
		-v $(CURDIR):/go/src/github.com/projectcalico/calico:rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

MAKE_DIRS=$(shell ls -d */)

clean:
	$(MAKE) -C api clean
	$(MAKE) -C apiserver clean
	$(MAKE) -C app-policy clean
	$(MAKE) -C calicoctl clean
	$(MAKE) -C cni-plugin clean
	$(MAKE) -C confd clean
	$(MAKE) -C felix clean
	$(MAKE) -C kube-controllers clean
	$(MAKE) -C libcalico-go clean
	$(MAKE) -C node clean
	$(MAKE) -C pod2daemon clean
	$(MAKE) -C typha clean
	$(MAKE) -C calico clean

generate:
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix gen-files
	$(MAKE) -C app-policy protobuf
	$(MAKE) -C calico gen-manifests

# Build all Calico images for the current architecture.
image:
	$(MAKE) -C pod2daemon image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C calicoctl image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C app-policy image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

###############################################################################
# Run local e2e smoke test against the checked-out code 
# using a local kind cluster.
###############################################################################
E2E_FOCUS ?= "sig-network.*Conformance"
e2e-test:
	$(MAKE) -C e2e build
	$(MAKE) -C node kind-k8st-setup
	KUBECONFIG=$(KIND_KUBECONFIG) ./e2e/bin/e2e.test -ginkgo.focus=$(E2E_FOCUS)

###############################################################################
# Release logic below
###############################################################################
# Build the release tool.
hack/release/release: $(shell find ./hack/release -type f -name '*.go')
	$(DOCKER_RUN) $(CALICO_BUILD) go build -v -o $@ ./hack/release/cmd

# Install ghr for publishing to github.
hack/release/ghr: 
	$(DOCKER_RUN) -e GOBIN=/go/src/$(PACKAGE_NAME)/hack/release/ $(CALICO_BUILD) go install github.com/tcnksm/ghr@v0.14.0

# Build a release.
release: hack/release/release 
	@hack/release/release -create

# test the release code
release-test:
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -cover -r hack/release/pkg

# Publish an already built release.
release-publish: hack/release/release hack/release/ghr
	@hack/release/release -publish

# Create a release branch.
create-release-branch: hack/release/release
	@hack/release/release -new-branch

gen-semaphore-yaml:
	cd .semaphore && ./generate-semaphore-yaml.sh
