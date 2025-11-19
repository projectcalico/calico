include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/libcalico-go

LOCAL_CHECKS = check-gen-files

KIND_CONFIG = $(KIND_DIR)/kind-single.config

NETPOL_CNP_TAG = main
NETPOL_CNP_CRD_URL = https://raw.githubusercontent.com/kubernetes-sigs/network-policy-api/refs/heads/$(NETPOL_CNP_TAG)/config/crd/standard
NETPOL_CNP_CRD = policy.networking.k8s.io_clusternetworkpolicies.yaml

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################

BINDIR?=bin

# Create a list of files upon which the generated file depends, skip the generated file itself
UPGRADE_SRCS := $(filter-out ./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go, \
                             $(wildcard ./lib/upgrade/migrator/clients/v1/k8s/custom/*.go))

# Create a list of files upon which the generated file depends, skip the generated file itself
APIS_SRCS := $(filter-out ./lib/apis/v3/zz_generated.deepcopy.go, $(wildcard ./lib/apis/v3/*.go))

.PHONY: clean
clean:
	rm -rf $(BINDIR) checkouts
	find . -name '*.coverprofile' -type f -delete

###############################################################################
# Building the binary
###############################################################################
GENERATED_FILES:=./lib/apis/v3/zz_generated.deepcopy.go \
	./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go \
	./lib/apis/v3/generated.openapi.go \
	./lib/apis/v1/generated.openapi.go \
	./lib/selector/tokenizer/kind_string.go

.PHONY: gen-files
## Force rebuild generated go utilities (e.g. deepcopy-gen) and generated files
gen-files: gen-crds
	rm -rf $(GENERATED_FILES)
	$(MAKE) $(GENERATED_FILES)
	$(MAKE) fix-changed

## Force a rebuild of custom resource definition yamls
gen-crds:
	rm -rf config/crd
	# Generate CRDs without descriptions
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) controller-gen crd:allowDangerousTypes=true,crdVersions=v1,deprecatedV1beta1CompatibilityPreserveUnknownFields=false,maxDescLen=0 paths=./lib/apis/... output:crd:dir=config/crd/'
	# Generate CRDs with descriptions, and place them into a temp directory
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) controller-gen crd:allowDangerousTypes=true,crdVersions=v1,deprecatedV1beta1CompatibilityPreserveUnknownFields=false paths=./lib/apis/... output:crd:dir=config/crd/crd-felix'
	# Copy over felix CRD with descriptions
	cp config/crd/crd-felix/crd.projectcalico.org_felixconfigurations.yaml config/crd
	# Cleanup
	rm -rf config/crd/crd-felix/
	rm -f config/crd/_.yaml
	rm -f config/crd/_nodes.yaml
	# Remove the first yaml separator line.
	$(DOCKER_GO_BUILD) sh -c 'find ./config/crd -name "*.yaml" | xargs sed -i 1d'
	# Add K8S ClusterNetworkPolicy CRD
	curl -sSfL --retry 3 $(NETPOL_CNP_CRD_URL)/$(NETPOL_CNP_CRD) -o ./config/crd/$(NETPOL_CNP_CRD)
	# Run prettier to fix indentation
	docker run --rm --user $(id -u):$(id -g) -v $(CURDIR)/config/crd/:/work/config/crd/ tmknom/prettier --write --parser=yaml /work
	# Patch in manual tweaks to the generated CRDs.
	patch -p2 < patches/0001-Add-nullable-to-IPAM-block-allocations-field.patch

./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go: $(UPGRADE_SRCS)
	$(DOCKER_GO_BUILD) sh -c 'deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "./docs/boilerplate.go.txt" \
		--bounding-dirs "github.com/projectcalico/calico/libcalico-go" \
		--output-file zz_generated.deepcopy.go \
		"$(PACKAGE_NAME)/lib/upgrade/migrator/clients/v1/k8s/custom"'

./lib/apis/v3/zz_generated.deepcopy.go: $(APIS_SRCS)
	$(DOCKER_GO_BUILD) sh -c 'deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "./docs/boilerplate.go.txt" \
		--bounding-dirs "github.com/projectcalico/calico/libcalico-go" \
		--output-file zz_generated.deepcopy.go \
		"$(PACKAGE_NAME)/lib/apis/v3"'

# Generate OpenAPI spec
./lib/apis/v3/generated.openapi.go: $(APIS_SRCS)
	$(DOCKER_GO_BUILD) \
           sh -c 'openapi-gen \
                --v 1 --logtostderr \
                --go-header-file "./docs/boilerplate.go.txt" \
				--output-dir "./lib/apis/v3" \
                --output-pkg "$(PACKAGE_NAME)/lib/apis/v3" \
                "$(PACKAGE_NAME)/lib/apis/v3" \
				"$(PACKAGE_NAME)/lib/apis/v1"'

	$(DOCKER_GO_BUILD) \
           sh -c 'openapi-gen \
                --v 1 --logtostderr \
                --go-header-file "./docs/boilerplate.go.txt" \
				--output-dir "./lib/apis/v1" \
                --output-pkg "$(PACKAGE_NAME)/lib/apis/v1" \
                "$(PACKAGE_NAME)/lib/apis/v1"'

./lib/selector/tokenizer/kind_string.go: ./lib/selector/tokenizer/tokenizer.go
	$(DOCKER_GO_BUILD) go generate ./lib/selector/tokenizer

###############################################################################
# Static checks
###############################################################################
# TODO: re-enable all linters
LINT_ARGS += --disable unused,errcheck,ineffassign,staticcheck

.PHONY: check-gen-files
check-gen-files: $(GENERATED_FILES) fix-changed gen-crds
	git diff --exit-code -- $(GENERATED_FILES) || (echo "The generated targets changed, please 'make gen-files' and commit the results"; exit 1)
	@if [ "$$(git status --porcelain config/crd)" != "" ]; then \
	echo "The following CRD file updates to be added"; git status --porcelain config/crd; exit 1; fi

.PHONY: check-format
check-format:
	@if $(DOCKER_GO_BUILD) goimports -l lib | grep -v zz_generated | grep .; then \
	  echo "Some files in ./lib are not goimported"; \
	  false ;\
	else \
	  echo "All files in ./lib are goimported"; \
	fi

###############################################################################
# Tests
###############################################################################
.PHONY: ut-cover
## Run the UTs natively with code coverage.  This requires a local etcd and local kubernetes master to be running.
ut-cover:
	./run-uts

WHAT?=.
GINKGO_FOCUS?=.*

.PHONY:ut
## Run the fast set of unit tests in a container.
ut:
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -skip "\[Datastore\]" -focus="$(GINKGO_FOCUS)" $(WHAT)'

.PHONY:fv
## Run functional tests against a real datastore in a container.
fv: fv-setup
	$(DOCKER_RUN) --privileged \
		-e KUBECONFIG=/kubeconfig.yaml \
		-v $(KIND_KUBECONFIG):/kubeconfig.yaml \
		--dns $(shell docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' coredns) \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -focus "$(GINKGO_FOCUS).*\[Datastore\]|\[Datastore\].*$(GINKGO_FOCUS)" $(WHAT)'
	$(MAKE) fv-teardown

## Run the setup required to run the FVs, but don't run any FVs.
.PHONY:fv-setup
fv-setup: run-etcd run-etcd-tls cluster-create run-coredns

## Teardown the FVs resources.
fv-teardown: stop-etcd stop-etcd-tls kind-cluster-destroy stop-coredns

## Run the FVs without any setup or teardown. Useful when writing FVs.
.PHONY:fv-fast
fv-fast:
	$(DOCKER_RUN) --privileged \
		-e KUBECONFIG=/kubeconfig.yaml \
		-v $(KIND_KUBECONFIG):/kubeconfig.yaml \
		--dns $(shell docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' coredns) \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -focus "$(GINKGO_FOCUS).*\[Datastore\]|\[Datastore\].*$(GINKGO_FOCUS)" $(WHAT)'

# Create a kind cluster, and deploy some resources required for the libcalico-go tests.
# TODO: Remove the need for this extra target, these should be created by the tests that need them.
cluster-create: kind-cluster-create
	@KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f test/mock-node.yaml
	@KUBECONFIG=$(KIND_KUBECONFIG) $(KUBECTL) apply -f test/namespaces.yaml

## Run an etcd with TLS enabled, needed for some libcalico-go UTs.
run-etcd-tls: stop-etcd-tls
	# TODO: We shouldn't need to enable the v2 API, but some of our test code
	# still relies on it.
	docker run --detach \
		-v $(CURDIR)/test/etcd-ut-certs:/root/etcd-certificates/ \
		--net=host \
		--entrypoint=/usr/local/bin/etcd \
		--name calico-etcd-tls $(ETCD_IMAGE)  \
		--listen-peer-urls https://127.0.0.1:5008 \
		--peer-cert-file=/root/etcd-certificates/server.crt \
		--peer-key-file=/root/etcd-certificates/server.key \
		--advertise-client-urls https://127.0.0.1:5007 \
		--listen-client-urls https://0.0.0.0:5007 \
		--trusted-ca-file=/root/etcd-certificates/ca.crt \
		--cert-file=/root/etcd-certificates/server.crt \
		--key-file=/root/etcd-certificates/server.key \
		--client-cert-auth=true \
		--enable-v2 \
		--data-dir=/var/lib/etcd

## Stop etcd with name calico-etcd-tls
stop-etcd-tls:
	-docker rm -f calico-etcd-tls

run-coredns: stop-coredns
	docker run \
		--detach \
		--name coredns \
		--rm \
		-v $(shell pwd)/test/coredns:/etc/coredns \
		-w /etc/coredns \
		coredns/coredns:$(COREDNS_VERSION)

stop-coredns:
	-docker rm -f coredns

st:
	@echo "No STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks test
