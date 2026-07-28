# Copyright (c) 2019-2024 Tigera, Inc. All rights reserved.

# This Makefile requires the following dependencies on the host system:
# - go
#
# TODO: Add in the necessary variables, etc, to make this Makefile work.
# TODO: Add in multi-arch stuff.

define yq_cmd
	$(shell yq --version | grep v$1.* >/dev/null && which yq || echo docker run --rm --user="root" -i -v "$(shell pwd)":/workdir mikefarah/yq:$1 $(if $(shell [ $1 -lt 4 ] && echo "true"), yq,))
endef
YQ_V4 = $(call yq_cmd,4)

GIT_CMD   = git
CURL_CMD  = curl -fL

ifdef CONFIRM
GIT       = $(GIT_CMD)
CURL      = $(CURL_CMD)
else
GIT       = echo [DRY RUN] $(GIT_CMD)
CURL      = echo [DRY RUN] $(CURL_CMD)
endif

# These values are used for fetching tools to run as part of the build process
# and shouldn't vary based on the target we're building for
NATIVE_ARCH := $(shell bash -c 'if [[ "$(shell uname -m)" == "x86_64" ]]; then echo amd64; else uname -m; fi')
NATIVE_OS := $(shell uname -s | tr A-Z a-z)

# The version of kustomize we use for generating bundles
KUSTOMIZE_VERSION = v5.6.0
KUSTOMIZE_DOWNLOAD_URL = https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2F$(KUSTOMIZE_VERSION)/kustomize_$(KUSTOMIZE_VERSION)_$(NATIVE_OS)_$(NATIVE_ARCH).tar.gz

# Our version of operator-sdk
OPERATOR_SDK_VERSION = v1.39.2
OPERATOR_SDK_URL = https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR_SDK_VERSION)/operator-sdk_$(NATIVE_OS)_$(NATIVE_ARCH)

# Our version of helm3 - Note that we use BUILD_ARCH here instead of NATIVE_ARCH because
# that's what we used before and we don't want to break things if that's necessary.
HELM3_VERSION = v3.11.3
HELM3_URL = https://get.helm.sh/helm-$(HELM3_VERSION)-$(NATIVE_OS)-$(BUILDARCH).tar.gz
HELM_BUILDARCH_BINARY = $(HACK_BIN)/helm-$(BUILDARCH)
HELM_BUILDARCH_VERSIONED_BINARY = $(HELM_BUILDARCH_BINARY)-$(HELM3_VERSION)


# The directory into which we download binaries we need to run certain
# processes, e.g. generating bundles
HACK_BIN ?= hack/bin
$(HACK_BIN):
	mkdir -p $(HACK_BIN)

# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: fmt vet ut

# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES ?= amd64 arm64 ppc64le s390x

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

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

# we want to be able to run the same recipe on multiple targets keyed on the image name
# to do that, we would use the entire image name, e.g. calico/node:abcdefg, as the stem, or '%', in the target
# however, make does **not** allow the usage of invalid filename characters - like / and : - in a stem, and thus errors out
# to get around that, we "escape" those characters by converting all : to --- and all / to ___ , so that we can use them
# in the target, we then unescape them back
escapefs = $(subst :,---,$(subst /,___,$(1)))
unescapefs = $(subst ---,:,$(subst ___,/,$(1)))

# list of arches *not* to build when doing *-all
EXCLUDEARCH ?=
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
GOEXPERIMENT=boringcrypto
TAGS=osusergo,netgo
else
CGO_ENABLED=0
endif

###############################################################################
REPO?=tigera/operator
PACKAGE_NAME?=github.com/tigera/operator
LOCAL_USER_ID?=$(shell id -u $$USER)
# The project Go version.
GO_VERSION?=1.25.12
# Version of Kubernetes to use for dependencies, tests, and kubectl.
K8S_VERSION?=v1.35.7
# The version of LLVM to use for the go-build image.
LLVM_VERSION?=18.1.8
# Calico toolchain versions and the calico/go-build image to use.
GO_BUILD_VER?=$(GO_VERSION)-llvm$(LLVM_VERSION)-k8s$(K8S_VERSION:v%=%)
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)-$(BUILDARCH)
SRC_FILES=$(shell find ./pkg -name '*.go')
SRC_FILES+=$(shell find ./api -name '*.go')
SRC_FILES+=$(shell find ./internal/ -name '*.go')
SRC_FILES+=$(shell find ./test -name '*.go')
SRC_FILES+=cmd/main.go

EXTRA_DOCKER_ARGS += -e GOPRIVATE=github.com/tigera/*
ifeq ($(GIT_USE_SSH),true)
	GIT_CONFIG_SSH ?= git config --global url."ssh://git@github.com/".insteadOf "https://github.com/";
endif

ifdef SSH_AUTH_SOCK
  EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif

ifneq ($(GOPATH),)
	# If the environment is using multiple comma-separated directories for gopath, use the first one, as that
	# is the default one used by go modules.
	GOMOD_CACHE = $(shell echo $(GOPATH) | cut -d':' -f1)/pkg/mod
else
	# If gopath is empty, default to $(HOME)/go.
	GOMOD_CACHE = $(HOME)/go/pkg/mod
endif

EXTRA_DOCKER_ARGS += -v $(GOMOD_CACHE):/go/pkg/mod:rw

CONTAINERIZED= mkdir -p .go-pkg-cache $(GOMOD_CACHE) && \
	docker run --rm \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOPATH=/go \
		-e GOCACHE=/go-cache \
		-e GOOS=linux \
		-e GOARCH=$(ARCH) \
		-e KUBECONFIG=/go/src/$(PACKAGE_NAME)/kubeconfig.yaml \
		-e ACK_GINKGO_RC=true \
		-e ACK_GINKGO_DEPRECATIONS=1.16.5 \
		-e GOTOOLCHAIN=go1.26.4+auto \
		-w /go/src/$(PACKAGE_NAME) \
		--net=host \
		$(EXTRA_DOCKER_ARGS)

DOCKER_RUN := $(CONTAINERIZED) $(CALICO_BUILD)

BUILD_IMAGE?=tigera/operator
BUILD_INIT_IMAGE?=tigera/operator-init

BUILD_DIR?=build/_output
BINDIR?=$(BUILD_DIR)/bin

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

IMAGE_REGISTRY?=quay.io
PUSH_IMAGE_PREFIXES?=quay.io/
RELEASE_PREFIXES?=
# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGE_PREFIXES+=$(RELEASE_PREFIXES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES?=""
PUSH_MANIFEST_IMAGE_PREFIXES=$(PUSH_IMAGE_PREFIXES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGE_PREFIXES=$(filter-out $(PUSH_MANIFEST_IMAGE_PREFIXES),$(PUSH_IMAGE_PREFIXES))


imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGE_PREFIXES)))

sub-single-push-%:
	docker push $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG)-$(ARCH))

## push all arches
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGE_PREFIXES)))
sub-manifest-%:
	docker manifest create $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG)) $(addprefix --amend ,$(addprefix $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))-,$(VALIDARCHES)))
	docker manifest push --purge $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))

## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGE_PREFIXES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGE_PREFIXES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGE_PREFIXES)))
sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*$(BUILD_IMAGE):$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(VALIDARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

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
ENVOY_GATEWAY_VERSION ?= v1.8.0
ENVOY_GATEWAY_PREFIX ?= tigera-gateway-api
ENVOY_GATEWAY_NAMESPACE ?= tigera-gateway
ENVOY_GATEWAY_RESOURCES = pkg/render/gatewayapi/gateway_api_resources.yaml

$(ENVOY_GATEWAY_RESOURCES): $(HACK_BIN)/helm-$(BUILDARCH)
	echo "---" > $@
	echo "apiVersion: v1" >> $@
	echo "kind: Namespace" >> $@
	echo "metadata:" >> $@
	echo "  name: $(ENVOY_GATEWAY_NAMESPACE)" >> $@
	$(HELM_BUILDARCH_BINARY) template $(ENVOY_GATEWAY_PREFIX) $(ENVOY_GATEWAY_HELM_CHART) \
		--version $(ENVOY_GATEWAY_VERSION) \
		-n $(ENVOY_GATEWAY_NAMESPACE) \
		--include-crds \
	>> $@

$(HELM_BUILDARCH_BINARY): $(HACK_BIN) $(HELM_BUILDARCH_VERSIONED_BINARY)
	$(info ░▒▓ symlink $(HELM_BUILDARCH_VERSIONED_BINARY) -> $(HELM_BUILDARCH_BINARY))
	@ln -sf helm-$(BUILDARCH)-$(HELM3_VERSION) $(HACK_BIN)/helm-$(BUILDARCH)

$(HELM_BUILDARCH_VERSIONED_BINARY): $(HACK_BIN)
	$(info ░▒▓ Downloading helm3 $(HELM3_VERSION) for $(BUILDARCH) to $(HELM_BUILDARCH_VERSIONED_BINARY))
	@rm -f $(HELM_BUILDARCH_VERSIONED_BINARY)
	@curl -fsSL --retry 5 $(HELM3_URL) | tar --extract --gzip -C $(HACK_BIN) --strip-components=1 $(NATIVE_OS)-$(BUILDARCH)/helm -O > $(HELM_BUILDARCH_VERSIONED_BINARY)
	@chmod a+x $(HELM_BUILDARCH_VERSIONED_BINARY)


build: $(BINDIR)/operator-$(ARCH)
$(BINDIR)/operator-$(ARCH): $(SRC_FILES) $(ENVOY_GATEWAY_RESOURCES) $(ISTIO_CHART_FILES)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -buildvcs=false -v -o $(BINDIR)/operator-$(ARCH) -tags "$(TAGS)" -ldflags "-X $(PACKAGE_NAME)/version.VERSION=$(GIT_VERSION) -s -w" ./cmd/main.go'
ifeq ($(ARCH), $(filter $(ARCH),amd64))
	$(CONTAINERIZED) $(CALICO_BUILD) sh -c 'strings $(BINDIR)/operator-$(ARCH) | grep '_Cfunc__goboringcrypto_' 1> /dev/null'
endif

.PHONY: image
image: build $(BUILD_IMAGE)

$(BUILD_IMAGE): $(BUILD_IMAGE)-$(ARCH)
$(BUILD_IMAGE)-$(ARCH): $(BINDIR)/operator-$(ARCH)
	docker buildx build --load --platform=linux/$(ARCH) --pull -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg GIT_VERSION=$(GIT_VERSION) -f build/Dockerfile .
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif

.PHONY: images
images: image

# Build the images for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) images ARCH=$*

.PHONY: image-init
image-init: image
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_INIT_IMAGE):latest
endif

BINDIR?=build/init/bin
$(BINDIR)/kubectl:
	mkdir -p $(BINDIR)
	curl -sSf -L --retry 5 https://dl.k8s.io/release/v1.30.5/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

kubectl: $(BINDIR)/kubectl

$(BINDIR)/kind:
	$(CONTAINERIZED) $(CALICO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install sigs.k8s.io/kind"

clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(ISTIO_CHART_FILES)
	rm -rf build/init/bin
	rm -rf hack/bin
	rm -rf .go-pkg-cache
	rm -rf .crds
	rm -f *-release-notes.md
	docker rmi -f $(shell docker images -f "reference=$(BUILD_IMAGE):latest*" -q) > /dev/null 2>&1 || true

###############################################################################
# Tests
###############################################################################
UT_DIR?=./pkg
FV_DIR?=./test
GINKGO_ARGS?= -v -trace -r
GINKGO_FOCUS?=.*

.PHONY: ut
ut: $(ENVOY_GATEWAY_RESOURCES) $(ISTIO_CHART_FILES)
	-mkdir -p .go-pkg-cache report
	$(CONTAINERIZED) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	ginkgo -focus="$(GINKGO_FOCUS)" $(GINKGO_ARGS) "$(UT_DIR)"'

## Run the functional tests
fv: cluster-create load-container-images run-fvs cluster-destroy
run-fvs: $(ENVOY_GATEWAY_RESOURCES) $(ISTIO_CHART_FILES)
	-mkdir -p .go-pkg-cache report
	$(CONTAINERIZED) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) \
	ginkgo -focus="$(GINKGO_FOCUS)" $(GINKGO_ARGS) "$(FV_DIR)"'

## Create a local kind dual stack cluster.
KIND_KUBECONFIG?=./kubeconfig.yaml
KINDEST_NODE_VERSION?=v1.30.4
cluster-create: $(BINDIR)/kubectl $(BINDIR)/kind
	# First make sure any previous cluster is deleted
	make cluster-destroy

	# Create a kind cluster.
	$(BINDIR)/kind create cluster \
	        --config ./deploy/kind-config.yaml \
	        --kubeconfig $(KIND_KUBECONFIG) \
	        --image kindest/node:$(KINDEST_NODE_VERSION)

	./deploy/scripts/ipv6_kind_cluster_update.sh
	# Deploy resources needed in test env.
	$(MAKE) deploy-crds

	# Wait for controller manager to be running and healthy.
	while ! KUBECONFIG=$(KIND_KUBECONFIG) $(BINDIR)/kubectl get serviceaccount default; do echo "Waiting for default serviceaccount to be created..."; sleep 2; done

FV_IMAGE_REGISTRY := docker.io
VERSION_TAG := release-v3.31
NODE_IMAGE := calico/node
APISERVER_IMAGE := calico/apiserver
CNI_IMAGE := calico/cni
FLEXVOL_IMAGE := calico/pod2daemon-flexvol
KUBECONTROLLERS_IMAGE := calico/kube-controllers
TYPHA_IMAGE := calico/typha
CSI_IMAGE := calico/csi
NODE_DRIVER_REGISTRAR_IMAGE := calico/node-driver-registrar
GOLDMANE_IMAGE := calico/goldmane
WHISKER_IMAGE := calico/whisker
WHISKER_BACKEND_IMAGE := calico/whisker-backend

.PHONY: calico-node.tar
calico-node.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(NODE_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(NODE_IMAGE):$(VERSION_TAG)

.PHONY: calico-apiserver.tar
calico-apiserver.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(APISERVER_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(APISERVER_IMAGE):$(VERSION_TAG)

.PHONY: calico-cni.tar
calico-cni.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(CNI_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(CNI_IMAGE):$(VERSION_TAG)

.PHONY: calico-pod2daemon-flexvol.tar
calico-pod2daemon-flexvol.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(FLEXVOL_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(FLEXVOL_IMAGE):$(VERSION_TAG)

.PHONY: calico-kube-controllers.tar
calico-kube-controllers.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(KUBECONTROLLERS_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(KUBECONTROLLERS_IMAGE):$(VERSION_TAG)

.PHONY: calico-typha.tar
calico-typha.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(TYPHA_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(TYPHA_IMAGE):$(VERSION_TAG)

.PHONY: calico-csi.tar
calico-csi.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(CSI_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(CSI_IMAGE):$(VERSION_TAG)

.PHONY: calico-node-driver-registrar.tar
calico-node-driver-registrar.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(NODE_DRIVER_REGISTRAR_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(NODE_DRIVER_REGISTRAR_IMAGE):$(VERSION_TAG)

.PHONY: calico-goldmane.tar
calico-goldmane.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(GOLDMANE_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(GOLDMANE_IMAGE):$(VERSION_TAG)

.PHONY: calico-goldmane.tar
calico-whisker.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(WHISKER_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(WHISKER_IMAGE):$(VERSION_TAG)

.PHONY: calico-goldmane.tar
calico-whisker-backend.tar:
	docker pull $(FV_IMAGE_REGISTRY)/$(WHISKER_BACKEND_IMAGE):$(VERSION_TAG)
	docker save --output $@ $(WHISKER_BACKEND_IMAGE):$(VERSION_TAG)

IMAGE_TARS := calico-node.tar \
	calico-apiserver.tar \
	calico-cni.tar \
	calico-pod2daemon-flexvol.tar \
	calico-kube-controllers.tar \
	calico-typha.tar \
	calico-csi.tar \
	calico-node-driver-registrar.tar \
	calico-goldmane.tar \
	calico-whisker.tar \
	calico-whisker-backend.tar

load-container-images: ./test/load_images_on_kind_cluster.sh $(IMAGE_TARS)
	# Load the latest tar files onto the currently running kind cluster.
	KUBECONFIG=$(KIND_KUBECONFIG) ./test/load_images_on_kind_cluster.sh $(IMAGE_TARS)
	# Restart the Calico containers so they launch with the newly loaded code.
	# TODO: We should be able to do this without restarting everything in kube-system.
	KUBECONFIG=$(KIND_KUBECONFIG) $(BINDIR)/kubectl delete pods -n kube-system --all

## Deploy CRDs needed for UTs.  CRDs needed by ECK that we don't use are not deployed.
## kubectl create is used for prometheus as a workaround for https://github.com/prometheus-community/helm-charts/issues/1500
## kubectl create is used for operator CRDS since the Installation API is large enough now that we hit the following error:
##
##   The CustomResourceDefinition "installations.operator.tigera.io" is invalid: metadata.annotations: Too long: must have at most 262144 bytes
##
deploy-crds: kubectl
	@export KUBECONFIG=$(KIND_KUBECONFIG) && \
		$(BINDIR)/kubectl create -f pkg/crds/operator/ && \
		$(BINDIR)/kubectl apply -f pkg/crds/calico/ && \
		$(BINDIR)/kubectl apply -f pkg/crds/enterprise/ && \
		$(BINDIR)/kubectl apply -f deploy/crds/elastic/elasticsearch-crd.yaml && \
		$(BINDIR)/kubectl apply -f deploy/crds/elastic/kibana-crd.yaml && \
		$(BINDIR)/kubectl create -f deploy/crds/prometheus

create-tigera-operator-namespace: kubectl
	KUBECONFIG=$(KIND_KUBECONFIG) $(BINDIR)/kubectl create ns tigera-operator

## Destroy local kind cluster
cluster-destroy: $(BINDIR)/kubectl $(BINDIR)/kind
	-$(BINDIR)/kind delete cluster
	rm -f $(KIND_KUBECONFIG)



###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
## Perform static checks on the code.
# Use the newer go-build image for lint because golangci-lint bundled in the
# 1.25.x image was built with Go 1.25 and refuses to lint code targeting
# Go 1.26.3. The binary build still uses GO_BUILD_VER (1.25.x) to ensure
# glibc compatibility with the runtime UBI image.
CALICO_BUILD_LINT ?= calico/go-build:1.26.3-llvm21.1.8-k8s1.35.5-$(BUILDARCH)
static-checks:
	$(CONTAINERIZED) $(CALICO_BUILD_LINT) golangci-lint run --timeout 5m

.PHONY: fix
## Fix static checks
fix:
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	goimports -w $(SRC_FILES)'

.PHONY: format-check
format-check:
	@$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	files=$$(gofmt -l ./pkg ./internal/controller ./api ./test); \
	[ "$$files" = "" ] && exit 0; \
	echo The following files need a format update:; \
	echo $$files; \
	echo Try running \"make fix\" and committing any changes; \
	exit 1'

.PHONY: dirty-check
dirty-check:
	@if [ "$$(git diff --stat)" != "" ]; then \
	echo "The following files are dirty"; git diff --stat; exit 1; fi
	@# Check that no new CRDs needed to be committed
	@if [ "$$(git status --porcelain pkg/crds)" != "" ]; then \
	echo "The following CRD files need to be added"; git status --porcelain pkg/crds; exit 1; fi

foss-checks:
	@echo Running $@...
	docker run --rm \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-w /go/src/$(PACKAGE_NAME)
		-e FOSSA_API_KEY=$(FOSSA_API_KEY) \
		$(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean format-check validate-gen-versions static-checks image-all test gen-files fix dirty-check test-crds

validate-gen-versions:
	make gen-versions
	make dirty-check

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
VERSION_REGEX := ^v[0-9]+\.[0-9]+\.[0-9]+$$
release-tag: var-require-all-RELEASE_TAG-GITHUB_TOKEN
	$(eval VALID_TAG := $(shell echo $(RELEASE_TAG) | grep -Eq "$(VERSION_REGEX)" && echo true))
	$(if $(VALID_TAG),,$(error $(RELEASE_TAG) is not a valid version. Please use a version in the format vX.Y.Z))

# Skip releasing if the image already exists.
	@if !$(MAKE) VERSION=$(RELEASE_TAG) release-check-image-exists; then \
		echo "Images for $(RELEASE_TAG) already exists"; \
		exit 0; \
	fi

	$(MAKE) release VERSION=$(RELEASE_TAG)
	$(MAKE) release-publish-images VERSION=$(RELEASE_TAG)
	$(MAKE) release-github VERSION=$(RELEASE_TAG)


release-notes: var-require-all-VERSION-GITHUB_TOKEN
	@docker build -t tigera/release-notes -f build/Dockerfile.release-notes .
	@docker run --rm -v $(CURDIR):/workdir -e	GITHUB_TOKEN=$(GITHUB_TOKEN) -e VERSION=$(VERSION) tigera/release-notes

## Tags and builds a release from start to finish.
release: release-prereqs
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif
	$(MAKE) release-build
	$(MAKE) release-verify

	@echo ""
	@echo "Release build complete. Next, push the produced images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish"
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
	if ! docker run $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION)-$(ARCH) --version | grep '^Operator: $(VERSION)$$'; then echo "Reported version:" `docker run $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION)-$(ARCH) --version ` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

release-check-image-exists: release-prereqs
	@echo "Checking if $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION) exists already"; \
	if docker manifest inspect $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION) >/dev/null; \
		then echo "Image $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION) already exists"; \
		exit 1; \
	else \
		echo "Image tag check passed; image does not already exist"; \
	fi

release-publish-images: release-prereqs release-check-image-exists
	# Push images.
	$(MAKE) push-all push-manifests push-non-manifests RELEASE=true IMAGETAG=$(VERSION)

release-github: release-notes hack/bin/gh
	@echo "Creating github release for $(VERSION)"
	hack/bin/gh release create $(VERSION) --title $(VERSION) --draft --notes-file $(VERSION)-release-notes.md
	@echo "$(VERSION) GitHub release created in draft state. Please review and publish: https://github.com/tigera/operator/releases/tag/$(VERSION) ."

GITHUB_CLI_VERSION?=2.62.0
hack/bin/gh:
	mkdir -p hack/bin
	curl -sSL -o hack/bin/gh.tgz https://github.com/cli/cli/releases/download/v$(GITHUB_CLI_VERSION)/gh_$(GITHUB_CLI_VERSION)_linux_amd64.tar.gz
	tar -zxvf hack/bin/gh.tgz -C hack/bin/ gh_$(GITHUB_CLI_VERSION)_linux_amd64/bin/gh --strip-components=2
	chmod +x $@
	rm hack/bin/gh.tgz

hack/bin/release-from: $(shell find ./hack/release-from -type f)
	mkdir -p hack/bin
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -buildvcs=false -o hack/bin/release-from ./hack/release-from'

release-from: hack/bin/release-from var-require-all-VERSION-OPERATOR_BASE_VERSION var-require-one-of-EE_IMAGES_VERSIONS-OS_IMAGES_VERSIONS
	hack/bin/release-from

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif

check-milestone: hack/bin/gh var-require-all-VERSION-GITHUB_TOKEN
	@gh extension install valeriobelli/gh-milestone
	@echo "Checking milestone $(VERSION) exists"
	$(eval MILESTONE_NUMBER := $(shell gh milestone list --query $(VERSION) --repo $(REPO) --state all --json title --jq '.[0].title' | grep $(VERSION)))
	$(if $(MILESTONE_NUMBER),,$(error Milestone $(VERSION) does not exist))
	@echo "Checking $(VERSION) milestone has no open PRs"
	$(eval OPEN_PRS := $(shell gh search prs --milestone $(VERSION) --repo $(REPO) --state open --json number --jq '.[].number'))
	$(if $(OPEN_PRS),$(error Milestone $(VERSION) has open PRs))
	@echo "Checking milestone $(VERSION) is closed"
	$(eval CLOSED_MILESTONE := $(shell gh milestone list --query $(VERSION) --repo $(REPO) --state closed --json title --jq '.[0].title' | grep $(VERSION)))
	$(if $(CLOSED_MILESTONE),,$(error Milestone $(VERSION) is not closed))

release-prep: check-milestone var-require-all-GIT_PR_BRANCH_BASE-GIT_REPO_SLUG-VERSION-CALICO_VERSION-COMMON_VERSION-CALICO_ENTERPRISE_VERSION
	$(YQ_V4) ".title = \"$(CALICO_ENTERPRISE_VERSION)\" | .components |= with_entries(select(.key | test(\"^(eck-|coreos-).*\") | not)) |= with(.[]; .version = \"$(CALICO_ENTERPRISE_VERSION)\")" -i config/enterprise_versions.yml
	$(YQ_V4) ".title = \"$(CALICO_VERSION)\" | .components.[].version = \"$(CALICO_VERSION)\"" -i config/calico_versions.yml
	sed -i "s/\"gcr.io.*\"/\"quay.io\/\"/g" pkg/components/images.go
	sed -i "s/\"gcr.io.*\"/\"quay.io\"/g" hack/gen-versions/main.go
	$(MAKE) gen-versions release-prep/create-and-push-branch release-prep/create-pr release-prep/set-pr-labels

GIT_REMOTE?=origin
ifneq ($(if $(GIT_REPO_SLUG),$(shell dirname $(GIT_REPO_SLUG)),), $(shell dirname `git config remote.$(GIT_REMOTE).url | cut -d: -f2`))
GIT_FORK_USER:=$(shell dirname `git config remote.$(GIT_REMOTE).url | cut -d: -f2`)
endif
GIT_PR_BRANCH_BASE?=$(if $(SEMAPHORE),$(SEMAPHORE_GIT_BRANCH),)
GIT_REPO_SLUG?=$(if $(SEMAPHORE),$(SEMAPHORE_GIT_REPO_SLUG),)
RELEASE_UPDATE_BRANCH?=$(if $(SEMAPHORE),semaphore-,)auto-build-updates-$(VERSION)
GIT_PR_BRANCH_HEAD?=$(if $(GIT_FORK_USER),$(GIT_FORK_USER):$(RELEASE_UPDATE_BRANCH),$(RELEASE_UPDATE_BRANCH))
release-prep/create-and-push-branch:
ifeq ($(shell git rev-parse --abbrev-ref HEAD),$(RELEASE_UPDATE_BRANCH))
	$(error Current branch is pull request head, cannot set it up.)
endif
	-git branch -D $(RELEASE_UPDATE_BRANCH)
	-$(GIT) push $(GIT_REMOTE) --delete $(RELEASE_UPDATE_BRANCH)
	git checkout -b $(RELEASE_UPDATE_BRANCH)
	$(GIT) add config/*_versions.yml hack/gen-versions/main.go pkg/components/* pkg/crds/*
	$(GIT) commit -m "Automatic version updates for $(VERSION) release"
	$(GIT) push $(GIT_REMOTE) $(RELEASE_UPDATE_BRANCH)

release-prep/create-pr:
	$(call github_pr_create,$(GIT_REPO_SLUG),[$(GIT_PR_BRANCH_BASE)] $(if $(SEMAPHORE), Semaphore,) Auto Release Update for $(VERSION),$(GIT_PR_BRANCH_HEAD),$(GIT_PR_BRANCH_BASE))
	echo 'Created release update pull request for $(VERSION): $(PR_NUMBER)'

release-prep/set-pr-labels:
	$(call github_pr_add_comment,$(GIT_REPO_SLUG),$(PR_NUMBER),/merge-when-ready release-note-not-required docs-not-required delete-branch)
	echo "Added labels to pull request $(PR_NUMBER): merge-when-ready, release-note-not-required, docs-not-required & delete-branch"

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
	@curl -fsSL -o $@ $(OPERATOR_SDK_URL)
	@chmod +x $@

$(OPERATOR_SDK_BARE): $(OPERATOR_SDK)
	$(info ░▒▓ Linking $(OPERATOR_SDK) to $(OPERATOR_SDK_BARE))
	@ln -f -s operator-sdk-$(OPERATOR_SDK_VERSION) $(OPERATOR_SDK_BARE)

## Generating code after API changes.
gen-files: manifests generate

OS_VERSIONS?=config/calico_versions.yml
EE_VERSIONS?=config/enterprise_versions.yml

.PHONY: gen-versions gen-versions-calico gen-versions-enterprise

gen-versions: gen-versions-calico gen-versions-enterprise

gen-versions-calico: $(BINDIR)/gen-versions update-calico-crds
	$(BINDIR)/gen-versions -os-versions=$(OS_VERSIONS) > pkg/components/calico.go

gen-versions-enterprise: $(BINDIR)/gen-versions update-enterprise-crds
	$(BINDIR)/gen-versions -ee-versions=$(EE_VERSIONS) > pkg/components/enterprise.go

$(BINDIR)/gen-versions: $(shell find ./hack/gen-versions -type f)
	mkdir -p $(BINDIR)
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go build -buildvcs=false -o $(BINDIR)/gen-versions ./hack/gen-versions'

# $(1) is the product
define prep_local_crds
    $(eval product := $(1))
	rm -rf pkg/crds/$(product)
	rm -rf .crds/$(product)
	mkdir -p pkg/crds/$(product)
	mkdir -p .crds/$(product)
endef

# $(1) is the github project
# $(2) is the branch or tag to fetch
# $(3) is the directory name to use
define fetch_crds
    $(eval project := $(1))
    $(eval branch := $(2))
    $(eval dir := $(3))
	@echo "Fetching $(dir) CRDs from $(project) branch $(branch)"
	git -C .crds/$(dir) clone --depth 1 --branch $(branch) --single-branch git@github.com:$(project).git ./
endef
define copy_crds
    $(eval dir := $(1))
		$(eval product := $(2))
	@cp $(dir)/libcalico-go/config/crd/* pkg/crds/$(product)/ && echo "Copied $(product) CRDs"
endef
define copy_eck_crds
    $(eval dir := $(1))
		$(eval product := $(2))
	@cp $(dir)/charts/tigera-operator/crds/eck/* pkg/crds/$(product)/ && echo "Copied $(product) ECK CRDs"
endef

.PHONY: read-libcalico-version read-libcalico-enterprise-version
.PHONY: update-calico-crds update-enterprise-crds
.PHONY: fetch-calico-crds fetch-enterprise-crds
.PHONY: prepare-for-calico-crds prepare-for-enterprise-crds

CALICO?=projectcalico/calico
CALICO_CRDS_DIR?=.crds/calico
DEFAULT_OS_CRDS_DIR?=.crds/calico
read-libcalico-calico-version:
	$(eval CALICO_BRANCH := $(shell $(CONTAINERIZED) $(CALICO_BUILD) \
	bash -c '$(GIT_CONFIG_SSH) \
	yq -e ".components.libcalico-go.version" config/calico_versions.yml'))
	if [ -z "$(CALICO_BRANCH)" ]; then echo "libcalico branch not defined"; exit 1; fi

update-calico-crds: fetch-calico-crds
	$(call copy_crds, $(CALICO_CRDS_DIR),"calico")

prepare-for-calico-crds:
	$(call prep_local_crds,"calico")

fetch-calico-crds: prepare-for-calico-crds read-libcalico-calico-version
	$(if $(filter $(DEFAULT_OS_CRDS_DIR),$(CALICO_CRDS_DIR)), $(call fetch_crds,$(CALICO),$(CALICO_BRANCH),"calico"))

CALICO_ENTERPRISE?=tigera/calico-private
ENTERPRISE_CRDS_DIR?=.crds/enterprise
DEFAULT_EE_CRDS_DIR=.crds/enterprise
read-libcalico-enterprise-version:
	$(eval CALICO_ENTERPRISE_BRANCH := $(shell $(CONTAINERIZED) $(CALICO_BUILD) \
	bash -c '$(GIT_CONFIG_SSH) \
	yq -e ".components.libcalico-go.version" config/enterprise_versions.yml'))
	if [ -z "$(CALICO_ENTERPRISE_BRANCH)" ]; then echo "libcalico enterprise branch not defined"; exit 1; fi

update-enterprise-crds: fetch-enterprise-crds
	$(call copy_crds,$(ENTERPRISE_CRDS_DIR),"enterprise")
	$(call copy_eck_crds,$(ENTERPRISE_CRDS_DIR),"enterprise")

prepare-for-enterprise-crds:
	$(call prep_local_crds,"enterprise")

fetch-enterprise-crds: prepare-for-enterprise-crds  read-libcalico-enterprise-version
	$(if $(filter $(DEFAULT_EE_CRDS_DIR),$(ENTERPRISE_CRDS_DIR)), $(call fetch_crds,$(CALICO_ENTERPRISE),$(CALICO_ENTERPRISE_BRANCH),"enterprise"))

.PHONY: prepull-image
prepull-image:
	@echo Pulling operator image...
	docker pull $(IMAGE_REGISTRY)/$(BUILD_IMAGE):v$(VERSION)

# Get the digest for the image. This target runs docker commands on the host since the
# build container doesn't have docker-in-docker. 'docker inspect' returns output like the example
# below. RepoDigests may have more than one entry so we need to filter.
# [
#     {
#         "Id": "sha256:34a1114040c03830da0a8d57f8d999deba26d8e31bda353aed201a375f68870b",
#         "RepoTags": [
#             "quay.io/tigera/operator:v1.3.1",
#             "..."
#         ],
#         "RepoDigests": [
#             "quay.io/tigera/operator@sha256:5e1d551b5a711592472f4a3cc4645698d5f826da4253f0d47cfa5d5b641a2e1a",
#             "..."
#         ],
#         ...
#     }
# ]
.PHONY: get-digest
get-digest: prepull-image
	@echo Getting operator image digest...
	$(eval OPERATOR_IMAGE_INSPECT=$(shell sh -c "docker image inspect $(IMAGE_REGISTRY)/$(BUILD_IMAGE):v$(VERSION) | base64 -w 0"))
	$(eval OPERATOR_MANIFEST_INSPECT=$(shell sh -c "docker manifest inspect $(IMAGE_REGISTRY)/$(BUILD_IMAGE):v$(VERSION) | base64 -w 0"))

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
	$(DOCKER_RUN) sh -c 'controller-gen crd paths="./api/..." output:crd:artifacts:config=config/crd/bases'
	for x in $$(find config/crd/bases/*); do sed -i -e '/creationTimestamp: null/d' -e '/^---/d' -e '/^\s*$$/d' $$x; done
	@docker run --rm --user $(id -u):$(id -g) -v $(CURDIR)/pkg/crds/operator/:/work/crds/operator/ tmknom/prettier --write --parser=yaml /work

# Run go fmt against code
fmt:
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go fmt ./...'

# Run go vet against code
vet:
	$(CONTAINERIZED) $(CALICO_BUILD) \
	sh -c '$(GIT_CONFIG_SSH) \
	go vet ./...'

mod-tidy:
	$(DOCKER_RUN) sh -c 'go mod tidy'

# Generate code
# We use the upstream latest release of controller-gen as this is compatible with golang 1.19+ and we have no need
# for custom projectcalico.org types.
generate:
	$(DOCKER_RUN) sh -c 'controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./api/..." && \
		controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./pkg/..." && \
		controller-gen object:headerFile="hack/boilerplate.go.txt" paths="./internal/controller/..."'
	-# Run fix because generate was removing `//go:build !ignore_autogenerated` from the generated files
	-# but then fix adds it back.
	$(MAKE) fix

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
	@curl -fsSL $(KUSTOMIZE_DOWNLOAD_URL) | tar -C $(HACK_BIN) --extract --gzip kustomize
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
	git checkout -- config/crd/bases

.PHONY: bundle-validate
bundle-validate: $(OPERATOR_SDK_BARE)
	$(OPERATOR_SDK_BARE) bundle validate bundle/$(VERSION)

.PHONY: bundle-manifests
bundle-manifests:
ifndef VERSION
	$(error VERSION is undefined - run using make $@ VERSION=X.Y.Z PREV_VERSION=D.E.F)
endif
ifndef PREV_VERSION
	$(error PREV_VERSION is undefined - run using make $@ VERSION=X.Y.Z PREV_VERSION=D.E.F)
endif
	$(eval EXTRA_DOCKER_ARGS += -e BUNDLE_CRD_DIR=$(BUNDLE_CRD_DIR) -e BUNDLE_DEPLOY_DIR=$(BUNDLE_DEPLOY_DIR))
	$(CONTAINERIZED) $(CALICO_BUILD) "hack/gen-bundle/get-manifests.sh"

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
	$(CONTAINERIZED) $(CALICO_BUILD) hack/gen-bundle/update-bundle.sh

# Build the bundle image.
.PHONY: bundle-build
bundle-image:
ifndef VERSION
	$(error VERSION is undefined - run using make $@ VERSION=X.Y.Z)
endif
	docker build -f bundle/bundle-v$(VERSION).Dockerfile -t tigera-operator-bundle:$(VERSION) bundle/


.PHONY: test-crds
test-crds: test-enterprise-crds test-calico-crds

# TODO: Improve this testing by comparing the individual source files
# with the yaml printed out, this will need to be a yaml diff since the
# fields won't necessarily be in the same order or indentation.
test-calico-crds: $(BINDIR)/operator-$(ARCH)
	$(BINDIR)/operator-$(ARCH) --print-calico-crds all >/dev/null 2>&1

# TODO: Improve this testing by comparing the individual source files
# with the yaml printed out, this will need to be a yaml diff since the
# fields won't necessarily be in the same order or indentation.
test-enterprise-crds: $(BINDIR)/operator-$(ARCH)
	$(BINDIR)/operator-$(ARCH) --print-enterprise-crds all >/dev/null 2>&1

# Always install the git hooks to prevent potentially problematic commits.
hooks_installed:=$(shell ./install-git-hooks)

.PHONY: install-git-hooks
install-git-hooks:
	./install-git-hooks

.PHONY: pre-commit
pre-commit:
	$(CONTAINERIZED) $(foreach ALTERNATE,$(shell cat $(shell git rev-parse --git-dir)/objects/info/alternates 2>/dev/null),-v $(ALTERNATE):$(ALTERNATE):ro) $(CALICO_BUILD) git-hooks/pre-commit-in-container

# var-set-% checks if there is a non empty variable for the value describe by %. If FAIL_NOT_SET is set, then var-set-%
# fails with an error message. If FAIL_NOT_SET is not set, then var-set-% appends a 1 to VARSET if the variable isn't
# set.
var-set-%:
	$(if $($*),$(eval VARSET+=1),$(if $(FAIL_NOT_SET),$(error $* is required but not set),))

# var-require is used to check if one or all of the variables are set in REQUIRED_VARS, and fails if not. The variables
# in REQUIRE_VARS are hyphen separated.
#
# If FAIL_NOT_SET is set, then all variables described in REQUIRED_VARS must be set for var-require to not fail,
# otherwise only one variable needs to be set for var-require to not fail.
var-require: $(addprefix var-set-,$(subst -, ,$(REQUIRED_VARS)))
	$(if $(VARSET),,$(error one of $(subst -, ,$(REQUIRED_VARS)) is not set or empty, but at least one is required))

# var-require-all-% checks if the there are non empty variables set for the hyphen separated values in %, and fails if
# there isn't a non empty variable for each given value. For instance, to require FOO and BAR both must be set you would
# call var-require-all-FOO-BAR.
var-require-all-%:
	$(MAKE) var-require REQUIRED_VARS=$* FAIL_NOT_SET=true

# var-require-one-of-% checks if the there are non empty variables set for the hyphen separated values in %, and fails
# there isn't a non empty variable for at least one of the given values. For instance, to require either FOO or BAR both
# must be set you would call var-require-all-FOO-BAR.
var-require-one-of-%:
	$(MAKE) var-require REQUIRED_VARS=$*

GITHUB_API_EXIT_ON_FAILURE?=1
# Call the github API. $(1) is the http method type for the https request, $(2) is the repo slug, and is $(3) is for json
# data (if omitted then no data is set for the request). If GITHUB_API_EXIT_ON_FAILURE is set then the macro exits with 1
# on failure. On success, the ENV variable GITHUB_API_RESPONSE will contain the response from github
define github_call_api
	$(eval CMD := $(CURL) -X $(1) \
		-H "Content-Type: application/json"\
		-H "Authorization: Bearer ${GITHUB_TOKEN}"\
		https://api.github.com/repos/$(2) $(if $(3),--data '$(3)',))
	$(eval GITHUB_API_RESPONSE := $(shell $(CMD) | sed -e 's/#/\\\#/g'))
	$(if $(GITHUB_API_EXIT_ON_FAILURE), $(if $(GITHUB_API_RESPONSE),,exit 1),)
endef

# Create the pull request. $(1) is the repo slug, $(2) is the title, $(3) is the head branch and $(4) is the base branch.
# If the call was successful then the ENV variable PR_NUMBER will contain the pull request number of the created pull request.
define github_pr_create
	$(eval JSON := {"title": "$(2)", "head": "$(3)", "base": "$(4)"})
	$(call github_call_api,POST,$(1)/pulls,$(JSON))
	$(eval PR_NUMBER := $(filter-out null,$(shell echo '$(GITHUB_API_RESPONSE)' | jq '.number')))
endef

# Create a comment on a pull request. $(1) is the repo slug, $(2) is the pull request number, and $(3) is the comment
# body.
define github_pr_add_comment
	$(eval JSON := {"body":"$(3)"})
	$(call github_call_api,POST,$(1)/issues/$(2)/comments,$(JSON))
endef

#####################################
#####################################
# ImageSet utility targets
.PHONY: clean-imageset
clean-imageset:
	rm -f $(BUILD_DIR)/*imageset*


ifdef VERSION
OPERATOR_IMAGE ?= $(IMAGE_REGISTRY)/$(BUILD_IMAGE):$(VERSION)
else
OPERATOR_IMAGE ?= $(BUILD_IMAGE):latest
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
calico_img_filter=list | grep -e /calico/ -e tigera/operator
enterprise_img_filter=list | grep -v -e calico
else
calico_img_filter=listcalico
enterprise_img_filter=listenterprise
endif

# This gen-imageset target only creates an ImageSet for the built-in registries and cannot be used
# to generate an ImageSet for an alternate registry.
# The operator used needs to be one that all images it references have been pushed to the registry,
# this even includes the operator which references a version of itself.
.PHONY: gen-imageset gen-enterprise-imageset gen-calico-imageset
gen-imageset: gen-enterprise-imageset gen-calico-imageset $(BUILD_DIR)
	@cat $(BUILD_DIR)/imageset-enterprise.yaml > $(BUILD_DIR)/imageset.yaml
	@echo "---" >> $(BUILD_DIR)/imageset.yaml
	@cat $(BUILD_DIR)/imageset-calico.yaml >> $(BUILD_DIR)/imageset.yaml
	@echo Imageset written to file $(BUILD_DIR)/imageset.yaml

.PHONY: gen-enterprise-imageset
gen-enterprise-imageset: $(BUILD_DIR)
	$(eval IMAGESET_VER = $(shell docker run $(OPERATOR_IMAGE) --version 2>/dev/null | \
		grep "Enterprise:" | sed -e 's/Enterprise://'))
	@echo Enterprise version: $(IMAGESET_VER)
	@echo "$$imageset_header" > $(BUILD_DIR)/imageset-enterprise.yaml
	@echo "  name: enterprise-$(IMAGESET_VER)" >> $(BUILD_DIR)/imageset-enterprise.yaml
	@echo "spec:" >> $(BUILD_DIR)/imageset-enterprise.yaml
	@echo "  images:" >> $(BUILD_DIR)/imageset-enterprise.yaml
	@docker run $(OPERATOR_IMAGE) --print-images=$(enterprise_img_filter) | \
	  grep -v "Failed to read" | \
	  grep -v -e fips | \
	while read -r line; do \
	  echo "Adding digest for $${line}"; \
	  digest=$$($(CRANE) digest $${line}$(double_quote)); \
	  echo "  - image: \"$$(echo $${line} | sed -e 's|^.*/\([^/]*/[^/]*\):.*$$|\1|')\"" >> $(BUILD_DIR)/imageset-enterprise.yaml; \
	  echo "    digest: $${digest}" >> $(BUILD_DIR)/imageset-enterprise.yaml; \
	done

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
	  grep -v -e fips | \
	while read -r line; do \
	  echo "Adding digest for $${line}"; \
	  digest=$$($(CRANE) digest $${line}$(double_quote)); \
	  echo "  - image: \"$$(echo $${line} | sed -e 's|^.*/\([^/]*/[^/]*\):.*$$|\1|')\"" >> $(BUILD_DIR)/imageset-calico.yaml; \
	  echo "    digest: $${digest}" >> $(BUILD_DIR)/imageset-calico.yaml; \
	done
ifeq ($(OLD_STYLE_PRINT_IMAGE),true)
	@docker run $(OPERATOR_IMAGE) --print-images=list | \
	  grep -v -e "Failed to read" -e fips | \
	  grep -e 'tigera/key-cert-provisioner' | \
	while read -r line; do \
	  echo "Adding digest for $${line}"; \
	  digest=$$($(CRANE) digest $${line}$(double_quote)); \
	  echo "  - image: \"$$(echo $${line} | sed -e 's|^.*/\([^/]*/[^/]*\):.*$$|\1|')\"" >> $(BUILD_DIR)/imageset-calico.yaml; \
	  echo "    digest: $${digest}" >> $(BUILD_DIR)/imageset-calico.yaml; \
	done
endif

### End of ImageSet utilities
