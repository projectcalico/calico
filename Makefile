###############################################################################
# This Makefile is the top-level Makefile for the calico repository.
# It is used for building and testing Calico as a whole.
###############################################################################

include metadata.mk
include lib.Makefile

## Build all Calico component images.
.PHONY: image
image:
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C goldmane image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C webhooks image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C whisker image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C whisker-backend image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

## Push all Calico component images.
.PHONY: push
push:
	$(MAKE) -C apiserver push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C goldmane push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C webhooks push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C whisker push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C whisker-backend push IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

## Build all Calico component images for the current architecture.
.PHONY: image-all
image-all:
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C goldmane image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C webhooks image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C whisker image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C whisker-backend image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

## Run all tests.
.PHONY: test
test:
	$(MAKE) -C apiserver test
	$(MAKE) -C cni-plugin test
	$(MAKE) -C kube-controllers test
	$(MAKE) -C node test
	$(MAKE) -C typha test
	$(MAKE) -C libcalico-go test
	$(MAKE) -C confd test
	$(MAKE) -C felix test

## Run all linting.
.PHONY: lint
lint:
	$(MAKE) -C apiserver lint
	$(MAKE) -C cni-plugin lint
	$(MAKE) -C kube-controllers lint
	$(MAKE) -C node lint
	$(MAKE) -C typha lint
	$(MAKE) -C libcalico-go lint
	$(MAKE) -C confd lint
	$(MAKE) -C felix lint

## Build all binaries.
.PHONY: bin
bin:
	$(MAKE) -C apiserver bin
	$(MAKE) -C cni-plugin bin
	$(MAKE) -C kube-controllers bin
	$(MAKE) -C node bin
	$(MAKE) -C typha bin
	$(MAKE) -C calicoctl bin
	$(MAKE) -C goldmane bin
	$(MAKE) -C webhooks bin
	$(MAKE) -C whisker bin
	$(MAKE) -C whisker-backend bin

## Clean all binaries and images.
.PHONY: clean
clean:
	$(MAKE) -C apiserver clean
	$(MAKE) -C cni-plugin clean
	$(MAKE) -C kube-controllers clean
	$(MAKE) -C node clean
	$(MAKE) -C typha clean
	$(MAKE) -C libcalico-go clean
	$(MAKE) -C confd clean
	$(MAKE) -C felix clean
	$(MAKE) -C calicoctl clean
	$(MAKE) -C goldmane clean
	$(MAKE) -C webhooks clean
	$(MAKE) -C whisker clean
	$(MAKE) -C whisker-backend clean

CHART_DESTINATION ?= ./bin

## Build helm charts.
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

## Run all tests in the repository.
.PHONY: st
st:
	$(MAKE) -C node st

## Run all tests in the repository.
.PHONY: fv
fv:
	$(MAKE) -C node fv
	$(MAKE) -C felix fv
	$(MAKE) -C typha fv
	$(MAKE) -C kube-controllers fv

## Build the operator.
.PHONY: operator
operator:
	$(MAKE) -C node operator

## Run all tests in the repository.
.PHONY: run-fv
run-fv:
	$(MAKE) -C node run-fv

## Run all tests in the repository.
.PHONY: run-st
run-st:
	$(MAKE) -C node run-st

## Run all tests in the repository.
.PHONY: run-k8s-test
run-k8s-test:
	$(MAKE) -C node run-k8s-test

## Build and run all tests.
.PHONY: ci
ci:
	$(MAKE) -C apiserver ci
	$(MAKE) -C cni-plugin ci
	$(MAKE) -C kube-controllers ci
	$(MAKE) -C node ci
	$(MAKE) -C typha ci

###############################################################################
# Release
###############################################################################
## Build and push all images.
.PHONY: release-images
release-images:
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

###############################################################################
# Run local e2e smoke test against the checked-out code
# using a local kind cluster.
###############################################################################
E2E_FOCUS ?= "sig-network.*Conformance|sig-calico.*Conformance|BGP"
E2E_SKIP ?= ""
E2E_PROCS ?= 4
K8S_NETPOL_SUPPORTED_FEATURES ?= "ClusterNetworkPolicy"
K8S_NETPOL_UNSUPPORTED_FEATURES ?= ""
CLUSTER_ROUTING ?= BIRD

## Build all test images, create a kind cluster, and deploy Calico on it.
.PHONY: kind-up
kind-up: kind-build-images
	$(MAKE) kind-cluster-create CALICO_API_GROUP=$(KIND_CALICO_API_GROUP)
	$(MAKE) kind-deploy

## Build images, create a kind cluster with v1 CRDs, deploy Calico, and run the
## v1-to-v3 migration test.
.PHONY: kind-migration-test
kind-migration-test:
	KIND_CALICO_API_GROUP=crd.projectcalico.org/v1 $(MAKE) kind-up
	$(REPO_ROOT)/hack/test/kind/migration/run_test.sh

## Tear down the local kind cluster.
.PHONY: kind-down
kind-down: kind-cluster-destroy

## Run e2e smoke test against the local kind cluster.
.PHONY: kind-test
kind-test:
	$(MAKE) -C node kind-test E2E_FOCUS=$(E2E_FOCUS) E2E_SKIP=$(E2E_SKIP) E2E_PROCS=$(E2E_PROCS)

## Run e2e smoke test against the local kind cluster.
.PHONY: kind-test-all
kind-test-all:
	$(MAKE) -C node kind-test-all E2E_FOCUS=$(E2E_FOCUS) E2E_SKIP=$(E2E_SKIP) E2E_PROCS=$(E2E_PROCS)

## Run e2e smoke test against the local kind cluster.
.PHONY: kind-test-k8s
kind-test-k8s:
	$(MAKE) -C node kind-test-k8s E2E_FOCUS=$(E2E_FOCUS) E2E_SKIP=$(E2E_SKIP) E2E_PROCS=$(E2E_PROCS)

## Run e2e smoke test against the local kind cluster.
.PHONY: kind-test-calico
kind-test-calico:
	$(MAKE) -C node kind-test-calico E2E_FOCUS=$(E2E_FOCUS) E2E_SKIP=$(E2E_SKIP) E2E_PROCS=$(E2E_PROCS)
