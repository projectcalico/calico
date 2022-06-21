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

generate:
	$(MAKE) gen-semaphore-yaml
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix gen-files
	$(MAKE) -C app-policy protobuf
	$(MAKE) gen-manifests

gen-manifests: bin/helm
	cd ./manifests && \
		OPERATOR_VERSION=$(OPERATOR_VERSION) \
		CALICO_VERSION=$(CALICO_VERSION) \
		./generate.sh

gen-semaphore-yaml:
	cd .semaphore && ./generate-semaphore-yaml.sh

# Build the tigera-operator helm chart.
chart: bin/tigera-operator-$(GIT_VERSION).tgz
bin/tigera-operator-$(GIT_VERSION).tgz: bin/helm $(shell find ./charts/tigera-operator -type f)
	bin/helm package ./charts/tigera-operator \
	--destination ./bin/ \
	--version $(GIT_VERSION) \
	--app-version $(GIT_VERSION)

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

# Test the release code
release-test:
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -cover -r hack/release/pkg

# Publish an already built release.
release-publish: hack/release/release hack/release/ghr
	@hack/release/release -publish

# Create a release branch.
create-release-branch: hack/release/release
	@hack/release/release -new-branch

## Kicks semaphore job which syncs github released helm charts with helm index file
.PHONY: helm-index
helm-index:
	@echo "Triggering semaphore workflow to update helm index."
	SEMAPHORE_PROJECT_ID=30f84ab3-1ea9-4fb0-8459-e877491f3dea \
			     SEMAPHORE_WORKFLOW_BRANCH=master \
			     SEMAPHORE_WORKFLOW_FILE=../releases/calico/helmindex/update_helm.yml \
			     $(MAKE) semaphore-run-workflow

## Generates release notes for the given version.
.PHONY: release-notes
release-notes:
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set)
endif
ifndef VERSION
	$(error VERSION must be set)
endif
	VERSION=$(VERSION) GITHUB_TOKEN=$(GITHUB_TOKEN) python2 ./hack/release/generate-release-notes.py

## Update the AUTHORS.md file.
update-authors:
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set)
endif
	@echo "# Calico authors" > AUTHORS.md
	@echo "" >> AUTHORS.md
	@echo "This file is auto-generated based on commit records reported" >> AUTHORS.md
	@echo "by git for the projectcalico/calico repository. It is ordered alphabetically." >> AUTHORS.md
	@echo "" >> AUTHORS.md
	@docker run -ti --rm --net=host \
		-v $(REPO_ROOT):/code \
		-w /code \
		-e GITHUB_TOKEN=$(GITHUB_TOKEN) \
		python:3 \
		bash -c '/usr/local/bin/python hack/release/get-contributors.py >> /code/AUTHORS.md'

###############################################################################
# Post-release validation
###############################################################################
POSTRELEASE_IMAGE=calico/postrelease
POSTRELEASE_IMAGE_CREATED=.calico.postrelease.created
$(POSTRELEASE_IMAGE_CREATED):
	cd hack/postrelease && docker build -t $(POSTRELEASE_IMAGE) .
	touch $@

postrelease-checks: $(POSTRELEASE_IMAGE_CREATED)
	$(DOCKER_RUN) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-e VERSION=$(VERSION) \
		-e FLANNEL_VERSION=$(FLANNEL_VERSION) \
		-e OPERATOR_VERSION=$(OPERATOR_VERSION) \
		$(POSTRELEASE_IMAGE) \
		sh -c "nosetests hack/postrelease -e "$(EXCLUDE_REGEX)" -s -v --with-xunit --xunit-file='postrelease-checks.xml' --with-timer $(EXTRA_NOSE_ARGS)"
