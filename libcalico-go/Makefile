include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/libcalico-go

LOCAL_CHECKS = goimports check-gen-files

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

# The path, inside libcalico-go, to the cert files required for etcdv3 fv test
TEST_CERT_PATH := test/etcd-ut-certs/

.PHONY: clean
clean:
	rm -rf .go-pkg-cache $(BINDIR) checkouts
	find . -name '*.coverprofile' -type f -delete

###############################################################################
# Building the binary
###############################################################################
GENERATED_FILES:=./lib/apis/v3/zz_generated.deepcopy.go \
	./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go \
	./lib/apis/v3/openapi_generated.go \
	./lib/apis/v1/openapi_generated.go

.PHONY: gen-files
## Force rebuild generated go utilities (e.g. deepcopy-gen) and generated files
gen-files: gen-crds
	rm -rf $(GENERATED_FILES)
	$(MAKE) $(GENERATED_FILES)
	$(MAKE) fix

## Force a rebuild of custom resource definition yamls
gen-crds:
	rm -rf config
	$(DOCKER_GO_BUILD) sh -c '$(GIT_CONFIG_SSH) controller-gen  crd:crdVersions=v1 paths=./lib/apis/... output:crd:dir=config/crd/'
	@rm config/crd/_.yaml
	patch -s -p0 < ./config.patch

./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go: $(UPGRADE_SRCS)
	$(DOCKER_GO_BUILD) sh -c 'deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "./docs/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/lib/upgrade/migrator/clients/v1/k8s/custom" \
		--bounding-dirs "github.com/projectcalico/calico/libcalico-go" \
		--output-file-base zz_generated.deepcopy'

./lib/apis/v3/zz_generated.deepcopy.go: $(APIS_SRCS)
	$(DOCKER_GO_BUILD) sh -c 'deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "./docs/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/lib/apis/v3" \
		--bounding-dirs "github.com/projectcalico/calico/libcalico-go" \
		--output-file-base zz_generated.deepcopy'

# Generate OpenAPI spec
./lib/apis/v3/openapi_generated.go: $(APIS_SRCS)
	$(DOCKER_GO_BUILD) \
           sh -c 'openapi-gen \
                --v 1 --logtostderr \
                --go-header-file "./docs/boilerplate.go.txt" \
                --input-dirs "$(PACKAGE_NAME)/lib/apis/v3,$(PACKAGE_NAME)/lib/apis/v1" \
                --output-package "$(PACKAGE_NAME)/lib/apis/v3"'

	$(DOCKER_GO_BUILD) \
           sh -c 'openapi-gen \
                --v 1 --logtostderr \
                --go-header-file "./docs/boilerplate.go.txt" \
                --input-dirs "$(PACKAGE_NAME)/lib/apis/v1" \
                --output-package "$(PACKAGE_NAME)/lib/apis/v1"'

###############################################################################
# Static checks
###############################################################################
# TODO: re-enable all linters
LINT_ARGS += --disable gosimple,unused,structcheck,errcheck,deadcode,varcheck,ineffassign,staticcheck,govet

.PHONY: check-gen-files
check-gen-files: $(GENERATED_FILES) fix gen-crds
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
		-v $(CURDIR)/$(KUBECONFIG):/kubeconfig.yaml \
		--dns $(shell docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' coredns) \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -focus "$(GINKGO_FOCUS).*\[Datastore\]|\[Datastore\].*$(GINKGO_FOCUS)" $(WHAT)'
	$(MAKE) stop-etcd-tls

## Run the setup required to run the FVs, but don't run any FVs.
.PHONY:fv-setup
fv-setup: run-etcd run-etcd-tls cluster-create run-coredns

## Run the FVs without any setup or teardown. Useful when writing FVs.
.PHONY:fv-fast
fv-fast:
	$(DOCKER_RUN) --privileged \
		-e KUBECONFIG=/kubeconfig.yaml \
		-v $(CURDIR)/$(KUBECONFIG):/kubeconfig.yaml \
		--dns $(shell docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' coredns) \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r -focus "$(GINKGO_FOCUS).*\[Datastore\]|\[Datastore\].*$(GINKGO_FOCUS)" $(WHAT)'

## Run etcd, with tls enabled, as a container (calico-etcd-tls)
run-etcd-tls: stop-etcd-tls
	docker run --detach \
		-v `pwd`/$(TEST_CERT_PATH):/root/etcd-certificates/ \
		--net=host \
		--entrypoint=/usr/local/bin/etcd \
		--name calico-etcd-tls quay.io/coreos/etcd:$(ETCD_VERSION)  \
		--listen-peer-urls https://127.0.0.1:5008 \
		--peer-cert-file=/root/etcd-certificates/server.crt \
		--peer-key-file=/root/etcd-certificates/server.key \
		--advertise-client-urls https://127.0.0.1:5007 \
		--listen-client-urls https://0.0.0.0:5007 \
		--trusted-ca-file=/root/etcd-certificates/ca.crt \
		--cert-file=/root/etcd-certificates/server.crt \
		--key-file=/root/etcd-certificates/server.key \
		--client-cert-auth=true \
		--data-dir=/var/lib/etcd

## Stop etcd with name calico-etcd-tls
stop-etcd-tls:
	-docker rm -f calico-etcd-tls

## Run etcd as a container (calico-etcd)
run-etcd: stop-etcd
	docker run --detach \
	--net=host \
	--entrypoint=/usr/local/bin/etcd \
	--name calico-etcd quay.io/coreos/etcd:$(ETCD_VERSION) \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Create a local kind dual stack cluster.
KUBECONFIG?=kubeconfig.yaml
cluster-create: $(BINDIR)/kubectl $(BINDIR)/kind
	# First make sure any previous cluster is deleted
	make cluster-destroy

	# Create a kind cluster.
	$(BINDIR)/kind create cluster \
		--config ./test/kind-config.yaml \
		--kubeconfig $(KUBECONFIG) \
		--image kindest/node:$(K8S_VERSION)

	# Deploy resources needed in test env.
	$(MAKE) deploy-test-resources

	# Wait for controller manager to be running and healthy.
	while ! KUBECONFIG=$(KUBECONFIG) $(BINDIR)/kubectl get serviceaccount default; do echo "Waiting for default serviceaccount to be created..."; sleep 2; done


## Deploy resources needed for UTs.
deploy-test-resources: $(BINDIR)/kubectl
	@export KUBECONFIG=$(KUBECONFIG) && \
		./$(BINDIR)/kubectl create -f config/crd && \
		./$(BINDIR)/kubectl create -f test/mock-node.yaml && \
		./$(BINDIR)/kubectl create -f test/namespaces.yaml

## Destroy local kind cluster
cluster-destroy: $(BINDIR)/kind
	-$(BINDIR)/kind delete cluster
	rm -f $(KUBECONFIG)

$(BINDIR)/kind:
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install sigs.k8s.io/kind"

$(BINDIR)/kubectl:
	mkdir -p $(BINDIR)
	curl -L https://storage.googleapis.com/kubernetes-release/release/$(K8S_VERSION)/bin/linux/amd64/kubectl -o $@
	chmod +x $(BINDIR)/kubectl

## Stop the etcd container (calico-etcd)
stop-etcd:
	-docker rm -f calico-etcd

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
