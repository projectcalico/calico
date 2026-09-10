# Copyright (c) 2019-2026 Tigera, Inc. All rights reserved.

# This Makefile requires the following dependencies on the host system:
# - go
#
# TODO: Add in the necessary variables, etc, to make this Makefile work.
# TODO: Add in multi-arch stuff.

# These values are used for fetching tools to run as part of the build process
# and shouldn't vary based on the target we're building for
NATIVE_ARCH := $(shell bash -c 'if [[ "$(shell uname -m)" == "x86_64" ]]; then echo amd64; else uname -m; fi')
NATIVE_OS := $(shell uname -s | tr A-Z a-z)

# The version of kustomize we use for generating bundles
KUSTOMIZE_VERSION = v5.8.1
KUSTOMIZE_DOWNLOAD_URL = https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F$(KUSTOMIZE_VERSION)/kustomize_$(KUSTOMIZE_VERSION)_$(NATIVE_OS)_$(NATIVE_ARCH).tar.gz

# Our version of operator-sdk
OPERATOR_SDK_VERSION = v1.42.2
OPERATOR_SDK_URL = https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$(NATIVE_OS)_$(NATIVE_ARCH)

# Our version of helm3 - Note that we use BUILD_ARCH here instead of NATIVE_ARCH because
# that's what we used before and we don't want to break things if that's necessary.
HELM3_VERSION = v3.21.3
HELM3_URL = https://get.helm.sh/helm-$(HELM3_VERSION)-$(NATIVE_OS)-$(BUILDARCH).tar.gz
HELM_BUILDARCH_BINARY = $(HACK_BIN)/helm-$(BUILDARCH)
HELM_BUILDARCH_VERSIONED_BINARY = $(HELM_BUILDARCH_BINARY)-$(HELM3_VERSION)


# The directory into which we download binaries we need to run certain
# processes, e.g. generating bundles
HACK_BIN ?= hack/bin
$(HACK_BIN):
	mkdir -p $(HACK_BIN)

PACKAGE_NAME = github.com/projectcalico/calico/operator

# The image and arches the ci/cd common targets in lib.Makefile read. The operator
# publishes alongside the other Calico component images, so the registries come from
# metadata.mk rather than an override here.
BUILD_IMAGES    = operator
ARCHES          = amd64 arm64 ppc64le s390x
BINARY_NAME    ?= operator

include ../metadata.mk

# The FV suite talks to the shared kind cluster from inside the build container,
# where the repo is mounted at /go/src/github.com/projectcalico/calico.
EXTRA_DOCKER_ARGS += -e KUBECONFIG=/go/src/github.com/projectcalico/calico/hack/test/kind/kind-kubeconfig.yaml

BUILD_DIR ?= build/_output
BINDIR    ?= $(BUILD_DIR)/bin

include ../lib.Makefile

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

###############################################################################
# Building the code
###############################################################################
.PHONY: build

# Get version from git.
ifeq ($(LOCAL_BUILD),true)
  GIT_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)-dev-build
else
  GIT_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)
endif

# The version, registry and image path the built operator resolves Calico images at. A
# release names it, since an operator-only release carries its own tag while still
# deploying the components of the release it patches. Anything else resolves the tag cd
# publishes for this branch; the kind rig passes what it just pushed.
ifneq ($(RELEASE),true)
CALICO_VERSION    ?= $(BRANCH_IMAGE_TAG)
endif
CALICO_REGISTRY   ?=
CALICO_IMAGE_PATH ?=
CALICO_LDFLAGS = -X $(PACKAGE_NAME)/pkg/components.CalicoRelease=$(CALICO_VERSION) \
                 -X $(PACKAGE_NAME)/pkg/components.calicoRegistry=$(CALICO_REGISTRY) \
                 -X $(PACKAGE_NAME)/pkg/components.calicoImagePath=$(CALICO_IMAGE_PATH)

# To update the Istio version, see "Updating the bundled version of Istio" in docs/common_tasks.md.
ISTIO_HELM_REPO ?= https://istio-release.storage.googleapis.com/charts
ISTIO_VERSION ?= 1.29.2
ISTIO_RESOURCES_DIR = pkg/render/istio
ISTIO_CHARTS = base istiod cni ztunnel
ISTIO_CHART_FILES = $(addprefix $(ISTIO_RESOURCES_DIR)/,$(addsuffix .tgz,$(ISTIO_CHARTS)))

.PHONY: istio_charts
istio_charts: $(ISTIO_CHART_FILES)

$(ISTIO_RESOURCES_DIR)/%.tgz:
	@echo "Downloading Istio chart $* version $(ISTIO_VERSION)..."
	@curl -fsSL -o $@ $(ISTIO_HELM_REPO)/$*-$(ISTIO_VERSION).tgz

# To update the Envoy Gateway version, see "Updating the bundled version of
# Envoy Gateway" in docs/common_tasks.md.
ENVOY_GATEWAY_HELM_CHART ?= oci://docker.io/envoyproxy/gateway-helm
ENVOY_GATEWAY_VERSION ?= v1.8.3
ENVOY_GATEWAY_CHART = pkg/render/gatewayapi/gateway-helm.tgz

$(ENVOY_GATEWAY_CHART): $(HACK_BIN)/helm-$(BUILDARCH)
	$(HELM_BUILDARCH_BINARY) pull $(ENVOY_GATEWAY_HELM_CHART) \
		--version $(ENVOY_GATEWAY_VERSION) \
		--destination pkg/render/gatewayapi/
	@mv pkg/render/gatewayapi/gateway-helm-$(ENVOY_GATEWAY_VERSION).tgz $@

# Loading the operator's Go packages needs the tarballs its go:embed
# directives point at, so anything outside this directory asks for them here.
.PHONY: embedded_charts
embedded_charts: $(ISTIO_CHART_FILES) $(ENVOY_GATEWAY_CHART)

$(HELM_BUILDARCH_BINARY): $(HELM_BUILDARCH_VERSIONED_BINARY)
	$(info ░▒▓ symlink $(HELM_BUILDARCH_VERSIONED_BINARY) -> $(HELM_BUILDARCH_BINARY))
	@ln -sf helm-$(BUILDARCH)-$(HELM3_VERSION) $(HACK_BIN)/helm-$(BUILDARCH)

$(HELM_BUILDARCH_VERSIONED_BINARY): | $(HACK_BIN)
	$(info ░▒▓ Downloading helm3 $(HELM3_VERSION) for $(BUILDARCH) to $(HELM_BUILDARCH_VERSIONED_BINARY))
	@rm -f $(HELM_BUILDARCH_VERSIONED_BINARY)
	@curl -fsSL --retry 5 $(HELM3_URL) | tar --extract --gzip -C $(HACK_BIN) --strip-components=1 $(NATIVE_OS)-$(BUILDARCH)/helm -O > $(HELM_BUILDARCH_VERSIONED_BINARY)
	@chmod a+x $(HELM_BUILDARCH_VERSIONED_BINARY)


build: $(BINDIR)/$(BINARY_NAME)-$(ARCH)
$(BINDIR)/$(BINARY_NAME)-$(ARCH): $(SRC_FILES) $(ENVOY_GATEWAY_CHART) $(ISTIO_CHART_FILES)
	mkdir -p $(BINDIR)
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -buildvcs=false -v -o $(BINDIR)/$(BINARY_NAME)-$(ARCH) -tags "$(TAGS)" -ldflags "-X $(PACKAGE_NAME)/version.VERSION=$(GIT_VERSION) $(CALICO_LDFLAGS) -s -w" ./cmd/'

OPERATOR_IMAGE_NAME = $(firstword $(BUILD_IMAGES))
IMAGE_BUILD_MARKER  = operator_container-$(ARCH).created

.PHONY: image images
image images: $(IMAGE_BUILD_MARKER)

$(BUILD_DIR)/LICENSE: ../LICENSE.md | $(BUILD_DIR)
	cp ../LICENSE.md $@

# register is order-only (|) so binfmt setup doesn't trigger unnecessary rebuilds.
$(IMAGE_BUILD_MARKER): $(BINDIR)/$(BINARY_NAME)-$(ARCH) $(BUILD_DIR)/LICENSE | register
	$(DOCKER_BUILD) --build-arg BINARY_NAME=$(BINARY_NAME) -t $(OPERATOR_IMAGE_NAME):latest-$(ARCH) -f build/Dockerfile .
	$(MAKE) retag-build-images-with-registries BUILD_IMAGES=$(BUILD_IMAGES) VALIDARCHES=$(ARCH) IMAGETAG=latest
ifeq ($(ARCH),amd64)
	docker tag $(OPERATOR_IMAGE_NAME):latest-$(ARCH) $(OPERATOR_IMAGE_NAME):latest
endif
	touch $@

# The component references are ldflags, which Make cannot see, so a build that
# changes them asks for the relink explicitly.
.PHONY: dev-image
dev-image:
	rm -f $(BINDIR)/$(BINARY_NAME)-$(ARCH) $(IMAGE_BUILD_MARKER)
	$(MAKE) image

.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(ISTIO_CHART_FILES)
	rm -rf $(ENVOY_GATEWAY_CHART)
	rm -rf build/init/bin
	rm -rf hack/bin
	rm -rf .go-pkg-cache
	rm -f *.created
	find . -type f -name 'release-*.log' -delete -o  -name '*release-notes.md' -delete
	docker rmi -f $(shell docker images -f "reference=$(OPERATOR_IMAGE_NAME):latest*" -q) > /dev/null 2>&1 || true

###############################################################################
# Tests
###############################################################################
UT_DIR?=./pkg
FV_DIR?=./test
GO_TEST_ARGS ?= -count 1

# The kind suite runs well past go test's 10 minute default, which the ginkgo CLI
# used to disable on our behalf.
FV_TEST_TIMEOUT ?= 60m

# Only the ginkgo suites accept -ginkgo.focus, so a focused run has to narrow
# UT_DIR/FV_DIR to those packages as well.
GINKGO_FOCUS ?=
GINKGO_FOCUS_ARG = $(if $(GINKGO_FOCUS),-ginkgo.focus="$(GINKGO_FOCUS)")
ENVTEST_K8S_VERSION?=1.34.x

# gotestsum, rather than the ginkgo CLI, because it writes one JUnit report from the
# directory it runs in. Ginkgo resolves its report path against each suite instead,
# which scatters the reports through the package tree where CI cannot collect them.
.PHONY: ut
ut: $(ENVOY_GATEWAY_CHART) $(ISTIO_CHART_FILES)
	-mkdir -p .go-pkg-cache report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	go install sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.22 && \
	export KUBEBUILDER_ASSETS=$$(setup-envtest use $(ENVTEST_K8S_VERSION) --bin-dir /tmp/envtest-bins -p path) && \
	gotestsum --format testname --junitfile report/operator_ut.xml -- $(UT_DIR)/... $(GO_TEST_ARGS) $(GINKGO_FOCUS_ARG)'

## Run the functional tests against a local kind cluster.
fv: kind-cluster-create deploy-crds load-container-images run-fvs kind-cluster-destroy
run-fvs: $(ENVOY_GATEWAY_CHART) $(ISTIO_CHART_FILES)
	-mkdir -p .go-pkg-cache report
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	gotestsum --format testname --junitfile report/operator_fv.xml -- $(FV_DIR)/... $(GO_TEST_ARGS) -timeout $(FV_TEST_TIMEOUT) $(FV_LDFLAGS) $(GINKGO_FOCUS_ARG)'

# The tag the FV suite's in-process operator resolves for the components below, and
# loads them into kind under. Stamped into the test binary the same way a real build
# stamps the operator.
FV_IMAGE_TAG ?= $(CALICO_VERSION)
FV_LDFLAGS    = -ldflags "-X $(PACKAGE_NAME)/pkg/components.CalicoRelease=$(FV_IMAGE_TAG)"
FV_IMAGES     = calico/calico calico/node calico/whisker

# Prefer the images built from this commit, which CI restores from its cache before
# the FV runs, and fall back to a pull for a local run that has none.
load-container-images: $(KIND)
	@for image in $(FV_IMAGES); do \
		if docker image inspect $$image:latest-$(ARCH) >/dev/null 2>&1; then \
			docker tag $$image:latest-$(ARCH) $$image:$(FV_IMAGE_TAG); \
		else \
			docker pull $$image:$(FV_IMAGE_TAG); \
		fi; \
		$(KIND) load docker-image --name $(KIND_NAME) $$image:$(FV_IMAGE_TAG); \
	done
	# Restart the Calico containers so they launch with the newly loaded code.
	# TODO: We should be able to do this without restarting everything in kube-system.
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) delete pods -n kube-system --all

## Deploy the CRDs the FVs need on top of the ones kind-cluster-create installs:
## every operator CRD, including the Enterprise-only kinds, plus prometheus.
## kubectl create is used for prometheus as a workaround for https://github.com/prometheus-community/helm-charts/issues/1500
## and for the operator CRDs since the Installation API is large enough to hit
##
##   The CustomResourceDefinition "installations.operator.tigera.io" is invalid: metadata.annotations: Too long: must have at most 262144 bytes
##
deploy-crds: $(KUBECTL)
	@export KUBECONFIG=$(KIND_KUBECONFIG) && \
		$(KUBECTL) apply --server-side -f pkg/crds/operator/ && \
		$(KUBECTL) create -f deploy/crds/prometheus

create-tigera-operator-namespace: $(KUBECTL)
	KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) create ns tigera-operator

###############################################################################
# Static checks
###############################################################################
# golangci-lint loads the operator's packages, so the embedded charts have to be on
# disk before lib.Makefile's recipe runs.
static-checks: $(ENVOY_GATEWAY_CHART) $(ISTIO_CHART_FILES)

.PHONY: format-check
format-check:
	@$(DOCKER_GO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	files=$$(gofmt -l ./pkg ./internal/controller ./api ./test); \
	[ "$$files" = "" ] && exit 0; \
	echo The following files need a format update:; \
	echo $$files; \
	echo Try running \"make fix-changed\" and committing any changes; \
	exit 1'

.PHONY: yaml-lint
## Lint YAML files
yaml-lint:
	@docker run --rm $$(tty -s && echo "-it" || echo) -v $(CURDIR):/data cytopia/yamllint:latest .

.PHONY: dirty-check
dirty-check:
	@if [ "$$(git diff --stat -- .)" != "" ]; then \
	echo "The following files are dirty"; git diff --stat -- .; exit 1; fi
	@# Check that no new CRDs or admission policies needed to be committed
	@if [ "$$(git status --porcelain pkg/crds pkg/admission)" != "" ]; then \
	echo "The following imported files need to be added"; git status --porcelain pkg/crds pkg/admission; exit 1; fi

foss-checks:
	@echo Running $@...
	docker run --rm \
		-v $(CURDIR)/..:/go/src/$(MODULE_ROOT):rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-w /go/src/$(PACKAGE_NAME)
		-e FOSSA_API_KEY=$(FOSSA_API_KEY) \
		$(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
# Not `test`, which lib.Makefile defines as `ut fv st`. The FV block runs the
# kind suite on its own. amd64 only here; the "Operator: multi-arch build"
# block covers the other arches.
ci: clean format-check static-checks image fmt vet ut gen-files fix-changed dirty-check test-crds

## Deploys images to registry
cd: image-all cd-common

###############################################################################
# Release
###############################################################################
# The component versions the operator deploys are baked into its binary, so a release is a
# rebuild rather than a retag of an image built for a different set of them.
## Build and tag the release images for the specified VERSION.
release-build: var-require-all-VERSION check-release-image-tags
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)

# The tag is compiled in, so a release that guessed it would ship an operator naming
# images that were never published.
.PHONY: check-release-image-tags
check-release-image-tags:
	@if [ -z "$(CALICO_VERSION)" ]; then \
		echo "A release must set CALICO_VERSION to the version its component images are published at."; \
		echo "For an operator-only release that is the release being patched, not VERSION."; \
		exit 1; \
	fi; \
	if [ "$(ALLOW_BRANCH_IMAGE_TAGS)" = "true" ]; then exit 0; fi; \
	if [ "$(CALICO_VERSION)" = "$(BRANCH_IMAGE_TAG)" ]; then \
		echo "A release must name the tag it publishes at, not the branch default $(BRANCH_IMAGE_TAG)."; \
		echo "Set CALICO_VERSION, build through the release tooling, or pass ALLOW_BRANCH_IMAGE_TAGS=true."; \
		exit 1; \
	fi

# The operator ships as part of a Calico release, so publishing it is the image push.
# A release run that resumes after a failure re-enters this, so an image already at
# this version is skipped rather than treated as an error.
.PHONY: release-publish
release-publish: operator-release-prereqs var-require-all-VERSION bin/crane
	@if $(REPO_ROOT)/hack/image-published $(CRANE_CMD) "$(DEV_REGISTRIES)" "$(BUILD_IMAGES)" "$(VERSION)" "$(VALIDARCHES)"; then \
		echo "$(BUILD_IMAGES):$(VERSION) is already published, skipping"; \
	else \
		$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM); \
	fi

# operator-release-prereqs checks the environment on top of lib.Makefile's own
# release-prereqs, which the release targets below also depend on.
operator-release-prereqs: release-prereqs
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif

###############################################################################
# Utilities
###############################################################################
.PHONY: operator-sdk
OPERATOR_SDK_BARE=hack/bin/operator-sdk
OPERATOR_SDK=$(OPERATOR_SDK_BARE)-$(OPERATOR_SDK_VERSION)

operator-sdk: $(OPERATOR_SDK_BARE)

$(OPERATOR_SDK):
	$(info ░▒▓ Downloading operator-sdk to $(OPERATOR_SDK))
	@mkdir -p hack/bin
	@$(call fetch_file,$(OPERATOR_SDK_URL),$@)
	@chmod +x $@

$(OPERATOR_SDK_BARE): $(OPERATOR_SDK)
	$(info ░▒▓ Linking $(OPERATOR_SDK) to $(OPERATOR_SDK_BARE))
	@ln -f -s operator-sdk-$(OPERATOR_SDK_VERSION) $(OPERATOR_SDK_BARE)

## Generating code after API changes.
gen-files: manifests generate

.PHONY: prepull-image
prepull-image:
	@echo Pulling operator image...
	docker pull $(DEV_REGISTRY)/$(OPERATOR_IMAGE_NAME):v$(VERSION)

# Get the digest for the image. This target runs docker commands on the host since the
# build container doesn't have docker-in-docker. 'docker inspect' returns output like the example
# below. RepoDigests may have more than one entry so we need to filter.
# [
#     {
#         "Id": "sha256:34a1114040c03830da0a8d57f8d999deba26d8e31bda353aed201a375f68870b",
#         "RepoTags": [
#             "quay.io/calico/operator:v3.32.0",
#             "..."
#         ],
#         "RepoDigests": [
#             "quay.io/calico/operator@sha256:5e1d551b5a711592472f4a3cc4645698d5f826da4253f0d47cfa5d5b641a2e1a",
#             "..."
#         ],
#         ...
#     }
# ]
.PHONY: get-digest
get-digest: prepull-image
	@echo Getting operator image digest...
	$(eval OPERATOR_IMAGE_INSPECT=$(shell sh -c "docker image inspect $(DEV_REGISTRY)/$(OPERATOR_IMAGE_NAME):v$(VERSION) | base64 -w 0"))
	$(eval OPERATOR_MANIFEST_INSPECT=$(shell sh -c "docker manifest inspect $(DEV_REGISTRY)/$(OPERATOR_IMAGE_NAME):v$(VERSION) | base64 -w 0"))

#####################################
#####################################
# Image URL to use all building/pushing image targets
IMG ?= controller:latest

# Run against the configured Kubernetes cluster in ~/.kube/config
run: generate fmt vet manifests
	go run ./cmd/main.go

# Install CRDs into a cluster
install: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

# Uninstall CRDs from a cluster
uninstall: manifests kustomize
	$(KUSTOMIZE) build config/crd | kubectl delete -f -

# Deploy controller in the configured Kubernetes cluster in ~/.kube/config
deploy: manifests kustomize
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

# Generate manifests e.g. CRD
# Can also generate RBAC and webhooks but that is not enabled currently.
manifests:
	# Prune stale CRDs so one whose Go type is gone leaves the tree too.
	rm -f pkg/crds/operator/*.yaml
	$(DOCKER_GO_BUILD) sh -c 'controller-gen crd paths="./api/..." output:crd:artifacts:config=pkg/crds/operator'
	for x in $$(find pkg/crds/operator/*); do sed -i -e '/creationTimestamp: null/d' -e '/^---/d' -e '/^\s*$$/d' $$x; done
	@docker run --rm --user $(id -u):$(id -g) -v $(CURDIR)/pkg/crds/operator/:/work/crds/operator/ tmknom/prettier --write --parser=yaml /work

# Run go fmt against code
fmt:
	$(DOCKER_GO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go fmt ./...'

# Run go vet against code
vet: $(ENVOY_GATEWAY_CHART) $(ISTIO_CHART_FILES)
	$(DOCKER_GO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go vet ./...'

# Generate code
# We use the upstream latest release of controller-gen as this is compatible with golang 1.19+ and we have no need
# for custom projectcalico.org types.
generate: $(ENVOY_GATEWAY_CHART) $(ISTIO_CHART_FILES)
	$(DOCKER_GO_BUILD) sh -c 'controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./api/..." && \
		controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./pkg/..." && \
		controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./internal/controller/..."'
	-# controller-gen drops `//go:build !ignore_autogenerated` from the generated
	-# files, and the formatter puts it back.
	$(MAKE) fix-changed

GO_GET_CONTAINER=docker run --rm \
		-v $(CURDIR)/$(BINDIR):/go/bin:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOPATH=/go \
		--net=host \
		$(EXTRA_DOCKER_ARGS) \
		$(CALICO_BUILD)

.PHONY: kustomize
KUSTOMIZE = $(HACK_BIN)/kustomize
kustomize: $(KUSTOMIZE)
$(KUSTOMIZE): $(HACK_BIN)
	$(info ░▒▓ Downloading kustomize $(KUSTOMIZE_VERSION) to $(KUSTOMIZE))
	@$(call fetch_file,$(KUSTOMIZE_DOWNLOAD_URL),$(HACK_BIN)/kustomize.tar.gz)
	@tar -C $(HACK_BIN) --extract --gzip -f $(HACK_BIN)/kustomize.tar.gz kustomize
	@rm $(HACK_BIN)/kustomize.tar.gz
	@chmod a+x $(KUSTOMIZE)


# Options for 'bundle-build'

# Set the channels to the current release branch, unless
# we got another one passed to us. Channel should be
# release-vX.YY
CHANNEL ?= $(shell git branch --show-current)
BUNDLE_CHANNEL = --channels=$(if \
		 $(findstring release-v1,$(CHANNEL)),$(CHANNEL),\
		 $(error Channel for bundle should be a release branch of the format 'release-vX.YY', not '$(CHANNEL)'))

# We only specify one channel so we don't need to set a
# default, but if we have one then include it.
ifneq ($(origin DEFAULT_CHANNEL), undefined)
BUNDLE_DEFAULT_CHANNEL := --default-channel=$(DEFAULT_CHANNEL)
endif

# Collate our metadata
BUNDLE_METADATA_OPTS ?= $(BUNDLE_CHANNEL) $(BUNDLE_DEFAULT_CHANNEL)

BUNDLE_BASE_DIR ?= $(BUILD_DIR)/bundle/$(VERSION)
BUNDLE_CRD_DIR ?= $(BUNDLE_BASE_DIR)/crds
BUNDLE_DEPLOY_DIR ?= $(BUNDLE_BASE_DIR)/deploy

## Create an operator bundle image.
# E.g., make bundle VERSION=1.13.1 PREV_VERSION=1.13.0 CHANNELS=release-v1.13 DEFAULT_CHANNEL=release-v1.13
.PHONY: bundle
bundle: bundle-generate bundle-crd-clean update-bundle bundle-validate bundle-image

.PHONY: bundle-crd-clean
bundle-crd-clean:
	git checkout -- pkg/crds/operator

.PHONY: bundle-validate
bundle-validate: $(OPERATOR_SDK_BARE)
	$(OPERATOR_SDK_BARE) bundle validate bundle/$(VERSION)

# The Calico release the bundle's manifests come from. GIT_VERSION cannot serve
# here: the bundle fetches manifests by git ref, and a describe of an untagged
# commit is not one.
BUNDLE_CALICO_VERSION ?= $(shell git describe --tags --abbrev=0)

.PHONY: bundle-manifests
bundle-manifests:
ifndef VERSION
	$(error VERSION is undefined - run using make $@ VERSION=X.Y.Z PREV_VERSION=D.E.F)
endif
ifndef PREV_VERSION
	$(error PREV_VERSION is undefined - run using make $@ VERSION=X.Y.Z PREV_VERSION=D.E.F)
endif
	$(eval EXTRA_DOCKER_ARGS += -e BUNDLE_CRD_DIR=$(BUNDLE_CRD_DIR) -e BUNDLE_DEPLOY_DIR=$(BUNDLE_DEPLOY_DIR) -e CALICO_VERSION=$(BUNDLE_CALICO_VERSION))
	$(DOCKER_GO_BUILD) "hack/gen-bundle/get-manifests.sh"

.PHONY: bundle-generate
bundle-generate: manifests $(KUSTOMIZE) $(OPERATOR_SDK_BARE) bundle-manifests
	$(OPERATOR_SDK_BARE) generate bundle \
		--crds-dir $(BUNDLE_CRD_DIR) \
		--deploy-dir $(BUNDLE_DEPLOY_DIR) \
		--version $(VERSION) \
		--verbose \
		--manifests \
		--package tigera-operator \
		--metadata \
		$(BUNDLE_METADATA_OPTS)

# Update a generated bundle so that it can be certified.
.PHONY: update-bundle
update-bundle: $(OPERATOR_SDK_BARE) get-digest
	$(eval EXTRA_DOCKER_ARGS += -e OPERATOR_IMAGE_INSPECT="$(OPERATOR_IMAGE_INSPECT)" -e OPERATOR_MANIFEST_INSPECT="$(OPERATOR_MANIFEST_INSPECT)" -e VERSION=$(VERSION) -e PREV_VERSION=$(PREV_VERSION))
	$(DOCKER_GO_BUILD) hack/gen-bundle/update-bundle.sh

# Build the bundle image.
.PHONY: bundle-build
bundle-image:
ifndef VERSION
	$(error VERSION is undefined - run using make $@ VERSION=X.Y.Z)
endif
	docker build -f bundle/bundle-v$(VERSION).Dockerfile -t tigera-operator-bundle:$(VERSION) bundle/


.PHONY: test-crds
test-crds: test-calico-crds

# TODO: Improve this testing by comparing the individual source files
# with the yaml printed out, this will need to be a yaml diff since the
# fields won't necessarily be in the same order or indentation.
test-calico-crds: $(BINDIR)/$(BINARY_NAME)-$(ARCH)
	$(BINDIR)/$(BINARY_NAME)-$(ARCH) --print-calico-crds all >/dev/null 2>&1

#####################################
#####################################
# ImageSet utility targets
.PHONY: clean-imageset
clean-imageset:
	rm -f $(BUILD_DIR)/*imageset*


ifdef VERSION
OPERATOR_IMAGE ?= $(DEV_REGISTRY)/$(OPERATOR_IMAGE_NAME):$(VERSION)
else
OPERATOR_IMAGE ?= $(OPERATOR_IMAGE_NAME):latest
endif

double_quote := $(shell echo '"')
CRANE=docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c $(double_quote)crane

define imageset_header
apiVersion: operator.tigera.io/v1
kind: ImageSet
metadata:
endef
export imageset_header

ifeq ($(OLD_STYLE_PRINT_IMAGE),true)
calico_img_filter=list | grep -e /calico/
else
calico_img_filter=listcalico
endif

# This gen-imageset target only creates an ImageSet for the built-in registries and cannot be used
# to generate an ImageSet for an alternate registry.
# The operator used needs to be one that all images it references have been pushed to the registry,
# this even includes the operator which references a version of itself.
.PHONY: gen-imageset gen-calico-imageset
gen-imageset: gen-calico-imageset $(BUILD_DIR)
	@cat $(BUILD_DIR)/imageset-calico.yaml > $(BUILD_DIR)/imageset.yaml
	@echo Imageset written to file $(BUILD_DIR)/imageset.yaml

.PHONY: gen-calico-imageset
gen-calico-imageset: $(BUILD_DIR)
	$(eval IMAGESET_VER = $(shell docker run $(OPERATOR_IMAGE) --version 2>/dev/null | \
		grep "Calico:" | sed -e 's/Calico://'))
	@echo Calico version: $(IMAGESET_VER)
	@echo "$$imageset_header" > $(BUILD_DIR)/imageset-calico.yaml
	@echo "  name: calico-$(IMAGESET_VER)" >> $(BUILD_DIR)/imageset-calico.yaml
	@echo "spec:" >> $(BUILD_DIR)/imageset-calico.yaml
	@echo "  images:" >> $(BUILD_DIR)/imageset-calico.yaml
	@docker run $(OPERATOR_IMAGE) --print-images=$(calico_img_filter) | \
	  grep -v "Failed to read" | \
	while read -r line; do \
	  echo "Adding digest for $${line}"; \
	  digest=$$($(CRANE) digest $${line}$(double_quote)); \
	  echo "  - image: \"$$(echo $${line} | sed -e 's|^.*/\([^/]*/[^/]*\):.*$$|\1|')\"" >> $(BUILD_DIR)/imageset-calico.yaml; \
	  echo "    digest: $${digest}" >> $(BUILD_DIR)/imageset-calico.yaml; \
	done
ifeq ($(OLD_STYLE_PRINT_IMAGE),true)
	@docker run $(OPERATOR_IMAGE) --print-images=list | \
	  grep -v -e "Failed to read" | \
	  grep -e 'tigera/key-cert-provisioner' | \
	while read -r line; do \
	  echo "Adding digest for $${line}"; \
	  digest=$$($(CRANE) digest $${line}$(double_quote)); \
	  echo "  - image: \"$$(echo $${line} | sed -e 's|^.*/\([^/]*/[^/]*\):.*$$|\1|')\"" >> $(BUILD_DIR)/imageset-calico.yaml; \
	  echo "    digest: $${digest}" >> $(BUILD_DIR)/imageset-calico.yaml; \
	done
endif

### End of ImageSet utilities
