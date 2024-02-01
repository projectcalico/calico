<<<<<<< HEAD
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
	rm -rf ./bin

ci-preflight-checks:
	$(MAKE) check-dockerfiles
	$(MAKE) check-language
	$(MAKE) generate
	$(MAKE) check-dirty

check-dockerfiles:
	./hack/check-dockerfiles.sh

check-language:
	./hack/check-language.sh

generate:
	$(MAKE) gen-semaphore-yaml
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix gen-files
	$(MAKE) -C calicoctl gen-crds
	$(MAKE) -C app-policy protobuf
	$(MAKE) gen-manifests

gen-manifests: bin/helm
	cd ./manifests && \
		OPERATOR_VERSION=$(OPERATOR_VERSION) \
		CALICO_VERSION=$(CALICO_VERSION) \
		./generate.sh

# Get operator CRDs from the operator repo, OPERATOR_BRANCH_NAME must be set
get-operator-crds: var-require-all-OPERATOR_BRANCH_NAME
	cd ./charts/tigera-operator/crds/ && \
	for file in operator.tigera.io_*.yaml; do echo "downloading $$file from operator repo" && curl -fsSL https://raw.githubusercontent.com/tigera/operator/${OPERATOR_BRANCH_NAME}/pkg/crds/operator/$${file%_crd.yaml}.yaml -o $${file}; done
	cd ./manifests/ocp/ && \
	for file in operator.tigera.io_*.yaml; do echo "downloading $$file from operator repo" && curl -fsSL https://raw.githubusercontent.com/tigera/operator/${OPERATOR_BRANCH_NAME}/pkg/crds/operator/$${file%_crd.yaml}.yaml -o $${file}; done

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
	$(call build_binary, ./hack/release/cmd, $@)

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

# Currently our openstack builds either build *or* build and publish,
# hence why we have two separate jobs here that do almost the same thing.
build-openstack: bin/yq
	$(eval VERSION=$(shell bin/yq '.version' charts/calico/values.yaml))
	$(info Building openstack packages for version $(VERSION))
	$(MAKE) -C hack/release/packaging release VERSION=$(VERSION)

publish-openstack: bin/yq
	$(eval VERSION=$(shell bin/yq '.version' charts/calico/values.yaml))
	$(info Publishing openstack packages for version $(VERSION))
	$(MAKE) -C hack/release/packaging release-publish VERSION=$(VERSION)

## Kicks semaphore job which syncs github released helm charts with helm index file
.PHONY: helm-index
helm-index:
	@echo "Triggering semaphore workflow to update helm index."
	SEMAPHORE_PROJECT_ID=30f84ab3-1ea9-4fb0-8459-e877491f3dea \
			     SEMAPHORE_WORKFLOW_BRANCH=master \
			     SEMAPHORE_WORKFLOW_FILE=../releases/calico/helmindex/update_helm.yml \
			     $(MAKE) semaphore-run-workflow

# Creates the tar file used for installing Calico on OpenShift.
bin/ocp.tgz: manifests/ocp/ bin/yq
	mkdir -p bin/tmp
	cp -r manifests/ocp bin/tmp/
	$(DOCKER_RUN) $(CALICO_BUILD) /bin/bash -c "                                        \
		for file in bin/tmp/ocp/*crd* ;                                                 \
        	do bin/yq -i 'del(.. | select(has(\"description\")).description)' \$$file ; \
        done"
	tar czvf $@ -C bin/tmp ocp
	rm -rf bin/tmp

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
		-e VPP_VERSION=$(VPP_VERSION) \
		-e OPERATOR_VERSION=$(OPERATOR_VERSION) \
		$(POSTRELEASE_IMAGE) \
		sh -c "nosetests hack/postrelease -e "$(EXCLUDE_REGEX)" -s -v --with-xunit --xunit-file='postrelease-checks.xml' --with-timer $(EXTRA_NOSE_ARGS)"
=======
# Copyright (c) 2021-2024 Tigera, Inc. All rights reserved.

PACKAGE_NAME    ?= github.com/tigera/key-cert-provisioner

GO_BUILD_VER    ?= v0.90
GIT_USE_SSH      = true

ORGANIZATION=tigera
SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_KEY_CERT_PROVISIONER_PROJECT_ID)

ARCHES=amd64 arm64

RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

DEV_REGISTRIES        ?= quay.io
RELEASE_REGISTRIES    ?= quay.io

KEY_CERT_PROVISIONER_IMAGE ?=tigera/key-cert-provisioner
TEST_SIGNER_IMAGE          ?=tigera/test-signer
BUILD_IMAGES               ?=$(KEY_CERT_PROVISIONER_IMAGE) $(TEST_SIGNER_IMAGE)

PUSH_IMAGES           ?= $(foreach registry,$(DEV_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))
RELEASE_IMAGES        ?= $(foreach registry,$(RELEASE_REGISTRIES),$(addprefix $(registry)/,$(BUILD_IMAGES)))

GO_FILES= $(shell sh -c "find pkg cmd -name \\*.go")
EXTRA_DOCKER_ARGS += -e GOPRIVATE=github.com/tigera/*

##############################################################################
# Download and include Makefile.common before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

GOFLAGS = -buildvcs=false
include Makefile.common

###############################################################################
# Build
###############################################################################
.PHONY: build
build: bin/key-cert-provisioner-$(ARCH) bin/test-signer-$(ARCH)

.PHONY: bin/key-cert-provisioner-$(ARCH)
bin/key-cert-provisioner-$(ARCH): $(GO_FILES)
	$(DOCKER_GO_BUILD) \
        sh -c '$(GIT_CONFIG_SSH) go build -o $@ -ldflags "$(LDFLAGS) -s -w" cmd/main.go'

.PHONY: bin/test-signer-$(ARCH)
bin/test-signer-$(ARCH): $(GO_FILES)
	$(DOCKER_GO_BUILD) \
        sh -c '$(GIT_CONFIG_SSH) go build -o $@ -ldflags "$(LDFLAGS) -s -w" test-signer/test-signer.go'

###############################################################################
# Image
###############################################################################
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

.PHONY: image
image: tigera/key-cert-provisioner tigera/test-signer-image

.PHONY: tigera/key-cert-provisioner
tigera/key-cert-provisioner: tigera/key-cert-provisioner-$(ARCH)
tigera/key-cert-provisioner-$(ARCH): build
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		-t tigera/key-cert-provisioner:latest-$(ARCH) \
		-f Dockerfile .
ifeq ($(ARCH),amd64)
	docker tag tigera/key-cert-provisioner:latest-$(ARCH) tigera/key-cert-provisioner:latest
endif

.PHONY: tigera/test-signer-image
tigera/test-signer-image: bin/test-signer-$(ARCH)
	docker buildx build --load --platform=linux/$(ARCH) --pull \
		-t tigera/test-signer:latest-$(ARCH) \
		-f test-signer/Dockerfile .
ifeq ($(ARCH),amd64)
	docker tag tigera/test-signer:latest-$(ARCH) tigera/test-signer:latest
endif

###############################################################################
# CI/CD
###############################################################################
ut: build
	$(DOCKER_GO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) \
			go test ./...'

ci: clean static-checks ut

cd: image-all cd-common

clean:
	rm -f Makefile.common*
	rm -rf .go-pkg-cache bin
	-docker image rm -f $$(docker images $(KEY_CERT_PROVISIONER_IMAGE) -a -q)
	-docker image rm -f $$(docker images $(TEST_SIGNER_IMAGE) -a -q)
>>>>>>> key-cert-provisioner/master
