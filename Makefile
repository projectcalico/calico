PACKAGE_NAME = github.com/projectcalico/calico

include metadata.mk
include lib.Makefile

DOCKER_RUN := mkdir -p ./.go-pkg-cache bin $(GOMOD_CACHE) && \
	docker run --rm \
		--net=host \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		$(DOCKER_GIT_WORKTREE_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e "GOFLAGS=$(GOFLAGS)" \
		-v $(CURDIR):/go/src/github.com/projectcalico/calico:rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

.PHONY: update-file-copyrights
update-file-copyrights:
ifndef BASE_BRANCH
	$(error BASE_BRANCH is not defined. Please set BASE_BRANCH to the target branch (e.g., 'main'))
endif
	# Update outdated copyrights for updated files.
	YEAR=$$(date +%Y); git diff --diff-filter=d --name-only $(BASE_BRANCH) | xargs sed -i "/Copyright (c) $$YEAR Tigera/!s/Copyright (c) \([0-9]\{4\}\)\(-[0-9]\{4\}\)\{0,1\} Tigera/Copyright (c) \1-$$YEAR Tigera/"
	# Add copyright to new files that don't have it.
	YEAR=$$(date +%Y); \
	git diff --name-only --diff-filter=A $(BASE_BRANCH) | grep '\.go$$' | \
	xargs -I {} sh -c 'if ! grep -q "Copyright (c)" "{}"; then sed "s/YEAR/'$$YEAR'/g" hack/copyright.template | (cat -; echo; cat "{}") > temp && mv temp "{}"; fi'

clean:
	rm -rf .dev-stamps/
	$(MAKE) -C api clean
	$(MAKE) -C apiserver clean
	$(MAKE) -C app-policy clean
	$(MAKE) -C calicoctl clean
	$(MAKE) -C cni-plugin clean
	$(MAKE) -C confd clean
	$(MAKE) -C felix clean
	$(MAKE) -C cmd/calico clean
	$(MAKE) -C kube-controllers clean
	$(MAKE) -C libcalico-go clean
	$(MAKE) -C node clean
	$(MAKE) -C pod2daemon clean
	$(MAKE) -C key-cert-provisioner clean
	$(MAKE) -C typha clean
	$(MAKE) -C release clean
	rm -rf ./bin .stamp.*

check-go-mod:
	$(DOCKER_GO_BUILD) ./hack/check-go-mod.sh

go-vet:
	# Go vet will check that libbpf headers can be found; make sure they're available.
	$(MAKE) -C felix clone-libbpf
	$(DOCKER_GO_BUILD) go vet --tags fvtests ./...

update-x-libraries:
	$(DOCKER_GO_BUILD) sh -c "go get golang.org/x/... && go mod tidy"

check-dockerfiles:
	./hack/check-dockerfiles.sh

check-images-availability: bin/crane bin/yq
	cd ./hack && ./check-images-availability.sh

check-language:
	./hack/check-language.sh

check-mockery-config:
	./hack/check-mockery-config.sh

check-ginkgo-v2:
	./hack/check-ginkgo-v2.sh

check-ocp-no-crds:
	@echo "Checking for files in manifests/ocp with CustomResourceDefinitions"
	@CRD_FILES_IN_OCP_DIR=$$(grep "^kind: CustomResourceDefinition" manifests/ocp/* -l || true); if [ ! -z "$$CRD_FILES_IN_OCP_DIR" ]; then echo "ERROR: manifests/ocp should not have any CustomResourceDefinitions, these files should be removed:"; echo "$$CRD_FILES_IN_OCP_DIR"; exit 1; fi

yaml-lint:
	@docker run --rm $$(tty -s && echo "-it" || echo) -v $(PWD):/data cytopia/yamllint:latest .

protobuf:
	$(MAKE) -C app-policy protobuf
	$(MAKE) -C cni-plugin protobuf
	$(MAKE) -C felix protobuf
	$(MAKE) -C pod2daemon protobuf
	$(MAKE) -C goldmane protobuf

generate:
	$(MAKE) gen-semaphore-yaml
	$(MAKE) gen-deps-files
	$(MAKE) protobuf
	$(MAKE) -C lib gen-files
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix gen-files
	$(MAKE) -C goldmane gen-files
	$(MAKE) get-operator-crds
	$(MAKE) gen-manifests
	$(MAKE) fix-changed

gen-manifests: bin/helm bin/yq
	cd ./manifests && ./generate.sh

# Get operator CRDs from the operator repo, OPERATOR_BRANCH must be set
get-operator-crds: var-require-all-OPERATOR_ORGANIZATION-OPERATOR_GIT_REPO-OPERATOR_BRANCH
	@echo ==============================================================================================================
	@echo === Pulling new operator CRDs from $(OPERATOR_ORGANIZATION)/$(OPERATOR_GIT_REPO) branch $(OPERATOR_BRANCH) ===
	@echo ==============================================================================================================
	cd ./charts/crd.projectcalico.org.v1/templates/ && \
	for file in operator.tigera.io_*.yaml; do \
		echo "downloading $$file from operator repo"; \
		curl -fsSL --retry 5 https://raw.githubusercontent.com/$(OPERATOR_ORGANIZATION)/$(OPERATOR_GIT_REPO)/$(OPERATOR_BRANCH)/pkg/imports/crds/operator/$${file} -o $${file}; \
		cp $${file} ../../projectcalico.org.v3/templates/$${file}; \
	done
	$(MAKE) fix-changed

gen-semaphore-yaml:
	$(DOCKER_GO_BUILD) sh -c "DEFAULT_BRANCH_OVERRIDE=$(DEFAULT_BRANCH_OVERRIDE) \
	                          SEMAPHORE_GIT_BRANCH=$(SEMAPHORE_GIT_BRANCH) \
	                          RELEASE_BRANCH_PREFIX=$(RELEASE_BRANCH_PREFIX) \
	                          go run ./hack/cmd/deps $(DEPS_ARGS) generate-semaphore-yamls"

GO_DIRS=$(shell ./hack/list-go-sources.sh dirs)
DEP_FILES=$(patsubst %, %/deps.txt, $(GO_DIRS))

gen-deps-files:
	$(MAKE) -j$$(nproc) $(DEP_FILES)

$(DEP_FILES): go.mod go.sum $(shell ./hack/list-go-sources.sh files) Makefile hack/cmd/deps/*
	@{ \
	  echo "!!! GENERATED FILE, DO NOT EDIT !!!" && \
	  echo "Run 'make gen-deps-files' to regenerate." && \
	  echo && \
	  grep '^go' go.mod && \
	  $(DOCKER_GO_BUILD) sh -c "go run ./hack/cmd/deps combined $(patsubst %/,%,$(dir $@))"; \
	} > $@

CHART_DESTINATION ?= ./bin

# Build helm charts.
chart: $(CHART_DESTINATION)/tigera-operator-$(GIT_VERSION).tgz \
			 $(CHART_DESTINATION)/projectcalico.org.v3-$(GIT_VERSION).tgz \
			 $(CHART_DESTINATION)/crd.projectcalico.org.v1-$(GIT_VERSION).tgz

$(CHART_DESTINATION)/tigera-operator-$(GIT_VERSION).tgz: bin/helm $(shell find ./charts/tigera-operator -type f)
	mkdir -p $(CHART_DESTINATION)
	bin/helm package ./charts/tigera-operator \
	--destination $(CHART_DESTINATION)/ \
	--version $(GIT_VERSION) \
	--app-version $(GIT_VERSION)

$(CHART_DESTINATION)/crd.projectcalico.org.v1-$(GIT_VERSION).tgz: bin/helm $(shell find ./charts/crd.projectcalico.org.v1/ -type f)
	mkdir -p $(CHART_DESTINATION)
	bin/helm package ./charts/crd.projectcalico.org.v1/ \
	--destination $(CHART_DESTINATION)/ \
	--version $(GIT_VERSION) \
	--app-version $(GIT_VERSION)

$(CHART_DESTINATION)/projectcalico.org.v3-$(GIT_VERSION).tgz: bin/helm $(shell find ./charts/projectcalico.org.v3/ -type f)
	mkdir -p $(CHART_DESTINATION)
	bin/helm package ./charts/projectcalico.org.v3/ \
	--destination $(CHART_DESTINATION)/ \
	--version $(GIT_VERSION) \
	--app-version $(GIT_VERSION)

###############################################################################
# Build & push workflow — build all images, tag with a custom tag, and
# optionally push to a remote registry.
#
# Images are only re-tagged / re-pushed when their docker image ID changes,
# and the operator is only rebuilt when its inputs change. This makes repeated
# runs fast when only one component has been modified.
#
# Usage:
#   make image                                              # build + tag as calico/<name>:<version>
#   make push DEV_IMAGE_PATH=myuser DEV_IMAGE_TAG=latest    # build + tag + push to myuser/<name>:latest
#
# Component images are independent targets, so `make -jN` builds them in
# parallel (e.g., `make -j4 push DEV_IMAGE_PATH=myuser`).
#
# To force a full rebuild, remove the stamp directory:
#   rm -rf .dev-stamps && make push ...
###############################################################################

.PHONY: image
## Build all component images and tag for dev registry. Supports make -jN for parallel builds.
image: $(KIND_IMAGE_MARKERS)
	@CALICO_IMAGES="$(KIND_CALICO_IMAGES)" \
	  DEV_IMAGE_PREFIX="$(DEV_IMAGE_PREFIX)" \
	  DEV_IMAGE_TAG="$(DEV_IMAGE_TAG)" \
	  ARCH="$(ARCH)" \
	  STAMP_DIR="$(DEV_STAMP_DIR)" \
	  $(REPO_ROOT)/hack/dev-build.sh --tag
	@STAMP_DIR="$(DEV_STAMP_DIR)" \
	  KIND_INFRA_DIR="$(KIND_INFRA_DIR)" \
	  OPERATOR_REPO="$(OPERATOR_ORGANIZATION)/$(OPERATOR_GIT_REPO)" \
	  OPERATOR_BRANCH="$(OPERATOR_BRANCH)" \
	  DEV_IMAGE_TAG="$(DEV_IMAGE_TAG)" \
	  DEV_IMAGE_REGISTRY="$(DEV_IMAGE_REGISTRY)" \
	  DEV_IMAGE_PATH="$(DEV_IMAGE_PATH)" \
	  $(REPO_ROOT)/hack/dev-build.sh --operator
	@echo "image complete"

.PHONY: push
## Push all tagged images to the remote registry.
push: image
	@DEV_IMAGES="$(DEV_CALICO_IMAGES) $(DEV_OPERATOR_IMAGE)" \
	  STAMP_DIR="$(DEV_STAMP_DIR)" \
	  $(REPO_ROOT)/hack/dev-build.sh --push

.PHONY: push-chart
## Package the tigera-operator helm chart with custom image refs and push to OCI registry.
push-chart: bin/helm
	@TAG="$(DEV_IMAGE_TAG)" \
	  REGISTRY="$(DEV_IMAGE_REGISTRY)" \
	  IMAGE_PATH="$(DEV_IMAGE_PATH)" \
	  HELM="$(REPO_ROOT)/bin/helm" \
	  $(REPO_ROOT)/.github/scripts/package-helm-chart.sh

###############################################################################
# Run local e2e smoke test against the checked-out code
# using a local kind cluster.
###############################################################################
E2E_PROCS ?= 4
E2E_TEST_CONFIG ?= e2e/config/kind.yaml
E2E_OUTPUT_DIR ?= report
E2E_JUNIT_REPORT ?= e2e_conformance.xml
K8S_NETPOL_SUPPORTED_FEATURES ?= "ClusterNetworkPolicy,ClusterNetworkPolicyNamedPorts"
K8S_NETPOL_UNSUPPORTED_FEATURES ?= ""
CLUSTER_ROUTING ?= BIRD

## Build all test images, create a kind cluster, and deploy Calico on it.
.PHONY: kind-up
kind-up:
	$(MAKE) -j$$(nproc) kind-build-images
	$(MAKE) kind-cluster-create CALICO_API_GROUP=$(KIND_CALICO_API_GROUP)
	$(MAKE) kind-deploy

## Build images, create a kind cluster with v1 CRDs, deploy Calico, and run the
## v1-to-v3 migration test.
.PHONY: kind-migration-test
kind-migration-test:
	KIND_CALICO_API_GROUP=crd.projectcalico.org/v1 $(MAKE) kind-up
	$(REPO_ROOT)/hack/test/kind/migration/run_test.sh

## Create a kind cluster and run the conformance e2e tests.
e2e-test:
	$(MAKE) -C e2e build
	CLUSTER_ROUTING=$(CLUSTER_ROUTING) $(MAKE) kind-up
	$(MAKE) e2e-run KUBECONFIG=$(KIND_KUBECONFIG)

## Create a kind cluster and run the ClusterNetworkPolicy specific e2e tests.
e2e-test-clusternetworkpolicy:
	$(MAKE) -C e2e build
	CLUSTER_ROUTING=$(CLUSTER_ROUTING) $(MAKE) kind-up
	$(MAKE) e2e-run-cnp KUBECONFIG=$(KIND_KUBECONFIG)

## Run the general e2e tests against the cluster at $KUBECONFIG.
## Callers must set KUBECONFIG explicitly (e.g. $(KIND_KUBECONFIG) for kind).
e2e-run:
	@if [ -z "$(KUBECONFIG)" ]; then echo "e2e-run: KUBECONFIG must be set"; exit 1; fi
	mkdir -p $(E2E_OUTPUT_DIR)
	KUBECONFIG=$(KUBECONFIG) go run github.com/onsi/ginkgo/v2/ginkgo -procs=$(E2E_PROCS) --junit-report=$(E2E_JUNIT_REPORT) --output-dir=$(E2E_OUTPUT_DIR)/ ./e2e/bin/k8s/e2e.test -- --calico.test-config=$(abspath $(E2E_TEST_CONFIG))

## Run the ClusterNetworkPolicy specific e2e tests against the cluster at $KUBECONFIG.
e2e-run-cnp:
	@if [ -z "$(KUBECONFIG)" ]; then echo "e2e-run-cnp: KUBECONFIG must be set"; exit 1; fi
	KUBECONFIG=$(KUBECONFIG) ./e2e/bin/clusternetworkpolicy/e2e.test \
	  -exempt-features=$(K8S_NETPOL_UNSUPPORTED_FEATURES) \
	  -supported-features=$(K8S_NETPOL_SUPPORTED_FEATURES)

###############################################################################
# Gateway API conformance
#
# Runs the upstream sigs.k8s.io/gateway-api conformance suite against
# Calico's Envoy-Gateway-based implementation on the cluster at $KUBECONFIG,
# and emits a ConformanceReport YAML for upstream submission.
#
# Caller must:
#   1. set KUBECONFIG (e.g. $(KIND_KUBECONFIG))
#   2. set GATEWAY_CONFORMANCE_VERSION to a Calico release tag (e.g. v3.31.5)
#      for upstream submissions; required by the gateway-api report schema.
#
# The default GATEWAY_CLASS_NAME ("tigera-gateway-class") matches what the
# tigera-operator provisions when the GatewayAPI CR omits gatewayClasses.
###############################################################################
GATEWAY_CONFORMANCE_VERSION ?=
GATEWAY_CLASS_NAME ?= tigera-gateway-class
GATEWAY_CONFORMANCE_PROFILES ?= GATEWAY-HTTP
GATEWAY_CONFORMANCE_MODE ?= default
GATEWAY_CONFORMANCE_REPORT ?= $(REPO_ROOT)/$(E2E_OUTPUT_DIR)/gateway-conformance-report.yaml
GATEWAY_CONFORMANCE_ORG ?= projectcalico
GATEWAY_CONFORMANCE_PROJECT ?= calico
GATEWAY_CONFORMANCE_URL ?= https://github.com/projectcalico/calico
GATEWAY_CONFORMANCE_CONTACT ?= https://github.com/projectcalico/calico/blob/master/GOVERNANCE.md
GATEWAY_API_CR ?= $(REPO_ROOT)/e2e/cmd/gateway/manifests/gatewayapi.yaml
GATEWAY_ENVOY_PROXY ?= $(REPO_ROOT)/e2e/cmd/gateway/manifests/envoyproxy.yaml
GATEWAY_METALLB_POOL ?= $(REPO_ROOT)/e2e/cmd/gateway/manifests/metallb-pool.yaml
# Name of the docker network kind binds to. The kind default is "kind".
GATEWAY_KIND_DOCKER_NETWORK ?= kind
# Calico's tigera-operator-provisioned GatewayClass doesn't populate
# .status.supportedFeatures, so the conformance suite's auto-inference returns
# an empty set and refuses to construct. Default to the curated envoy-gateway
# set (see e2e/cmd/gateway/e2e_test.go::envoyGatewayCuratedSet) since Calico's
# implementation is a Calico-deployed Envoy Gateway and inherits its supported
# feature surface verbatim. Override GATEWAY_CONFORMANCE_CURATED to "" and set
# the individual flags below for ad-hoc / debugging runs.
GATEWAY_CONFORMANCE_CURATED ?= envoy-gateway
GATEWAY_CONFORMANCE_ALL_FEATURES ?= false
GATEWAY_CONFORMANCE_SUPPORTED_FEATURES ?=
GATEWAY_CONFORMANCE_EXEMPT_FEATURES ?=

## Apply the GatewayAPI operator CR and wait for the default GatewayClass to be Accepted.
##
## The tigera-operator reconciles the GatewayAPI CR asynchronously: it
## installs the Gateway API CRDs (gatewayclasses, gateways, httproutes, ...),
## installs the Envoy Gateway controller, and only then creates the default
## GatewayClass. `kubectl wait --for=condition` against a resource type that
## doesn't yet exist on the server errors immediately rather than retrying,
## so we poll for the CRD first, then wait for the GatewayClass.
GATEWAY_SETUP_CRD_TIMEOUT ?= 300
GATEWAY_SETUP_GWC_TIMEOUT ?= 5m

.PHONY: e2e-gateway-setup
e2e-gateway-setup:
	@if [ -z "$(KUBECONFIG)" ]; then echo "e2e-gateway-setup: KUBECONFIG must be set"; exit 1; fi
	@# Compute an L2 metallb pool from the kind docker bridge subnet so the
	@# conformance test runner (which lives on the host) can reach LB IPs.
	@# Calico's default metallb pool is BGP-mode + public IPs that aren't
	@# routable from the host. Mirrors envoyproxy/gateway's create-cluster.sh.
	@subnet_v4=$$(docker network inspect $(GATEWAY_KIND_DOCKER_NETWORK) 2>/dev/null | jq -r '.[].IPAM.Config[]? | select(.Subnet | contains(":") | not) | .Subnet' | head -1); \
	if [ -z "$$subnet_v4" ]; then \
	  echo "e2e-gateway-setup: could not determine IPv4 subnet of docker network '$(GATEWAY_KIND_DOCKER_NETWORK)'. Is the kind cluster up and is jq installed?"; \
	  exit 1; \
	fi; \
	prefix=$$(echo "$$subnet_v4" | awk -F. '{print $$1"."$$2"."$$3}'); \
	range="$$prefix.200-$$prefix.250"; \
	echo "Applying L2 metallb pool gateway-conformance with addresses $$range (from $(GATEWAY_KIND_DOCKER_NETWORK) subnet $$subnet_v4)"; \
	sed "s|__LB_RANGE_V4__|$$range|g" $(GATEWAY_METALLB_POOL) | kubectl --kubeconfig=$(KUBECONFIG) apply -f -
	kubectl --kubeconfig=$(KUBECONFIG) apply -f $(GATEWAY_API_CR)
	@echo "Waiting up to $(GATEWAY_SETUP_CRD_TIMEOUT)s for tigera-operator to install Gateway API CRDs..."
	@# The gatewayapi controller renders CRDs early (gatewayapi_controller.go:221)
	@# but only renders the tigera-gateway namespace + non-CRD resources AFTER
	@# resolving every envoyProxyRef (line 419, after the read at line 350). With
	@# envoyProxyRef set on first reconcile the operator returns early at line 351
	@# with "EnvoyProxy ... not found", so the namespace never lands. We unblock
	@# this by pre-creating the namespace ourselves once the EnvoyProxy CRD is
	@# in, then dropping the EnvoyProxy CR in. The next reconcile finds it and
	@# the operator owns the namespace from then on.
	@end=$$(( $$(date +%s) + $(GATEWAY_SETUP_CRD_TIMEOUT) )); \
	until kubectl --kubeconfig=$(KUBECONFIG) get crd gatewayclasses.gateway.networking.k8s.io >/dev/null 2>&1 \
	   && kubectl --kubeconfig=$(KUBECONFIG) get crd envoyproxies.gateway.envoyproxy.io >/dev/null 2>&1; do \
	  if [ $$(date +%s) -ge $$end ]; then \
	    echo "Timed out waiting for Gateway API + EnvoyProxy CRDs"; \
	    kubectl --kubeconfig=$(KUBECONFIG) get gatewayapi default -o yaml || true; \
	    kubectl --kubeconfig=$(KUBECONFIG) get tigerastatus || true; \
	    kubectl --kubeconfig=$(KUBECONFIG) -n tigera-operator logs deploy/tigera-operator --tail=200 || true; \
	    exit 1; \
	  fi; \
	  sleep 5; \
	done
	@echo "Pre-creating tigera-gateway namespace so the EnvoyProxy CR can be applied before the operator reconciles past the EnvoyProxyRef check"
	kubectl --kubeconfig=$(KUBECONFIG) create namespace tigera-gateway --dry-run=client -o yaml | kubectl --kubeconfig=$(KUBECONFIG) apply -f -
	kubectl --kubeconfig=$(KUBECONFIG) apply -f $(GATEWAY_ENVOY_PROXY)
	@echo "Waiting up to $(GATEWAY_SETUP_GWC_TIMEOUT) for $(GATEWAY_CLASS_NAME) GatewayClass to be created..."
	@end=$$(( $$(date +%s) + 300 )); \
	until kubectl --kubeconfig=$(KUBECONFIG) get gatewayclass $(GATEWAY_CLASS_NAME) >/dev/null 2>&1; do \
	  if [ $$(date +%s) -ge $$end ]; then \
	    echo "Timed out waiting for gatewayclass/$(GATEWAY_CLASS_NAME) to exist"; \
	    kubectl --kubeconfig=$(KUBECONFIG) get gatewayclass || true; \
	    exit 1; \
	  fi; \
	  sleep 5; \
	done
	kubectl --kubeconfig=$(KUBECONFIG) wait --for=condition=Accepted=true --timeout=$(GATEWAY_SETUP_GWC_TIMEOUT) gatewayclass/$(GATEWAY_CLASS_NAME)

## Run the Gateway API conformance suite. Requires e2e-gateway-setup to have completed.
e2e-run-gateway-conformance:
	@if [ -z "$(KUBECONFIG)" ]; then echo "e2e-run-gateway-conformance: KUBECONFIG must be set"; exit 1; fi
	@if [ -z "$(GATEWAY_CONFORMANCE_VERSION)" ]; then echo "WARNING: GATEWAY_CONFORMANCE_VERSION is empty; report.implementation.version will be blank and is not acceptable for upstream submission."; fi
	mkdir -p $(dir $(GATEWAY_CONFORMANCE_REPORT))
	KUBECONFIG=$(KUBECONFIG) ./e2e/bin/gateway/e2e.test \
	  -gateway-class=$(GATEWAY_CLASS_NAME) \
	  -curated=$(GATEWAY_CONFORMANCE_CURATED) \
	  -conformance-profiles=$(GATEWAY_CONFORMANCE_PROFILES) \
	  -mode=$(GATEWAY_CONFORMANCE_MODE) \
	  -all-features=$(GATEWAY_CONFORMANCE_ALL_FEATURES) \
	  -supported-features=$(GATEWAY_CONFORMANCE_SUPPORTED_FEATURES) \
	  -exempt-features=$(GATEWAY_CONFORMANCE_EXEMPT_FEATURES) \
	  -organization=$(GATEWAY_CONFORMANCE_ORG) \
	  -project=$(GATEWAY_CONFORMANCE_PROJECT) \
	  -url=$(GATEWAY_CONFORMANCE_URL) \
	  -contact=$(GATEWAY_CONFORMANCE_CONTACT) \
	  -version=$(GATEWAY_CONFORMANCE_VERSION) \
	  -report-output=$(GATEWAY_CONFORMANCE_REPORT) \
	  -test.v -test.timeout=60m

## End-to-end: build, kind-up, deploy Envoy Gateway, run conformance, emit report.
.PHONY: e2e-test-gateway-conformance
e2e-test-gateway-conformance:
	$(MAKE) -C e2e bin/gateway/e2e.test
	CLUSTER_ROUTING=$(CLUSTER_ROUTING) $(MAKE) kind-up
	$(MAKE) e2e-gateway-setup KUBECONFIG=$(KIND_KUBECONFIG)
	$(MAKE) e2e-run-gateway-conformance KUBECONFIG=$(KIND_KUBECONFIG)

###############################################################################
# Release logic below
###############################################################################
.PHONY: release release-publish create-release-branch release-test build-openstack publish-openstack release-notes
# Build the release tool.
release/bin/release: $(shell find ./release -type f -name '*.go')
	$(MAKE) -C release

# Prepare for a release (update version references, charts, manifests).
release-prep: release/bin/release bin/gh
	@OPERATOR_BRANCH=$(OPERATOR_BRANCH) release/bin/release release prep

# Install ghr for publishing to github.
bin/ghr:
	$(DOCKER_RUN) -e GOBIN=/go/src/$(PACKAGE_NAME)/bin/ $(CALICO_BUILD) go install github.com/tcnksm/ghr@$(GHR_VERSION)

# Install GitHub CLI
bin/gh:
	@mkdir -p bin
	@curl -sSL --retry 5 -o bin/gh.tgz https://github.com/cli/cli/releases/download/v$(GITHUB_CLI_VERSION)/gh_$(GITHUB_CLI_VERSION)_linux_amd64.tar.gz
	@tar -zxvf bin/gh.tgz -C bin/ gh_$(GITHUB_CLI_VERSION)_linux_amd64/bin/gh --strip-components=2
	@chmod +x $@
	@rm bin/gh.tgz

# Build a release.
release: release/bin/release
	@release/bin/release release build

# Publish an already built release.
release-publish: release/bin/release bin/ghr bin/helm
	@release/bin/release release publish

release-public: bin/gh release/bin/release
	@release/bin/release release public

# Create a release branch.
create-release-branch: release/bin/release
	@release/bin/release branch cut

# Test the release code
release-test:
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -cover -r hack/release/pkg

# Currently our openstack builds either build *or* build and publish,
# hence why we have two separate jobs here that do almost the same thing.
build-openstack: bin/yq
	$(eval VERSION=$(shell bin/yq '.version' charts/calico/values.yaml))
	$(info Building openstack packages for version $(VERSION))
	$(MAKE) -C release/packaging release VERSION=$(VERSION)

publish-openstack: bin/yq
	$(eval VERSION=$(shell bin/yq '.version' charts/calico/values.yaml))
	$(info Publishing openstack packages for version $(VERSION))
	$(MAKE) -C release/packaging release-publish VERSION=$(VERSION)

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
	tar czvf $@ --exclude='.gitattributes' -C manifests/ ocp

## Generates release notes for the given version.
.PHONY: release-notes
release-notes:
	@$(MAKE) -C release release-notes

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
		bash -c '/usr/local/bin/python release/get-contributors.py >> /code/AUTHORS.md'

update-pins: update-go-build-pin update-calico-base-pin

###############################################################################
# Post-release validation
###############################################################################
bin/gotestsum:
	@GOBIN=$(REPO_ROOT)/bin go install gotest.tools/gotestsum@$(GOTESTSUM_VERSION)

postrelease-checks release-validate: release/bin/release bin/gotestsum
	@release/bin/release release validate
