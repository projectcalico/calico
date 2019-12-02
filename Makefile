PACKAGE_NAME=github.com/projectcalico/libcalico-go
GO_BUILD_VER=v0.28

# libcalico-go still relies on vendoring
GOMOD_VENDOR = true
LOCAL_CHECKS = vendor goimports check-gen-files

###############################################################################
# Download and include Makefile.common
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

include Makefile.common

###############################################################################

K8S_VERSION      ?= v1.16.0
BINDIR           ?= bin

# Create a list of files upon which the generated file depends, skip the generated file itself
UPGRADE_SRCS := $(filter-out ./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go, \
                             $(wildcard ./lib/upgrade/migrator/clients/v1/k8s/custom/*.go))

# Create a list of files upon which the generated file depends, skip the generated file itself
APIS_SRCS := $(filter-out ./lib/apis/v3/zz_generated.deepcopy.go, $(wildcard ./lib/apis/v3/*.go))

# The path, inside libcalico-go, to the cert files required for etcdv3 fv test
TEST_CERT_PATH := test/etcd-ut-certs/

.PHONY: clean
clean:
	rm -rf .go-pkg-cache vendor $(BINDIR) checkouts
	find . -name '*.coverprofile' -type f -delete

###############################################################################
# Building the binary
###############################################################################
# Build the vendor directory.
vendor: mod-download
	$(DOCKER_GO_BUILD) go mod vendor

GENERATED_FILES:=./lib/apis/v3/zz_generated.deepcopy.go \
           ./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go

.PHONY: gen-files
## Force rebuild generated go utilities (e.g. deepcopy-gen) and generated files
gen-files:
	rm -rf $(GENERATED_FILES)
	$(MAKE) $(GENERATED_FILES)

$(BINDIR)/deepcopy-gen: vendor
	$(DOCKER_GO_BUILD) sh -c 'go build -o $@ $(PACKAGE_NAME)/vendor/k8s.io/code-generator/cmd/deepcopy-gen'

./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go: $(UPGRADE_SRCS) $(BINDIR)/deepcopy-gen
	$(DOCKER_GO_BUILD) sh -c '$(BINDIR)/deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "./docs/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/lib/upgrade/migrator/clients/v1/k8s/custom" \
		--bounding-dirs "github.com/projectcalico/libcalico-go" \
		--output-file-base zz_generated.deepcopy'

./lib/apis/v3/zz_generated.deepcopy.go: $(APIS_SRCS) $(BINDIR)/deepcopy-gen
	$(DOCKER_GO_BUILD) sh -c '$(BINDIR)/deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "./docs/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/lib/apis/v3" \
		--bounding-dirs "github.com/projectcalico/libcalico-go" \
		--output-file-base zz_generated.deepcopy'

###############################################################################
# Static checks
###############################################################################
# TODO: re-enable all linters
LINT_ARGS += --disable gosimple,unused,structcheck,errcheck,deadcode,varcheck,ineffassign,staticcheck,govet

.PHONY: check-gen-files
check-gen-files: $(GENERATED_FILES)
	git diff --exit-code -- $(GENERATED_FILES) || (echo "The generated targets changed, please 'make gen-files' and commit the results"; exit 1)

.PHONY: check-format
# Depends on the vendor directory because goimports needs to be able to resolve the imports.
check-format: vendor
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
ut-cover: vendor
	./run-uts

WHAT?=.
GINKGO_FOCUS?=.*

.PHONY:ut
## Run the fast set of unit tests in a container.
ut: vendor
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) \
		sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r --skipPackage vendor -skip "\[Datastore\]" -focus="$(GINKGO_FOCUS)" $(WHAT)'

.PHONY:fv
## Run functional tests against a real datastore in a container.
fv: vendor run-etcd run-etcd-tls run-kubernetes-master run-coredns
	$(DOCKER_RUN) --privileged --dns \
		$(shell docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' coredns) \
		$(CALICO_BUILD) sh -c 'cd /go/src/$(PACKAGE_NAME) && ginkgo -r --skipPackage vendor -focus "$(GINKGO_FOCUS).*\[Datastore\]|\[Datastore\].*$(GINKGO_FOCUS)" $(WHAT)'
	$(MAKE) stop-etcd-tls

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

## Run a local kubernetes master with API via hyperkube
run-kubernetes-master: stop-kubernetes-master
	# Run a Kubernetes apiserver using Docker.
	docker run \
		--net=host --name st-apiserver \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube kube-apiserver \
			--bind-address=0.0.0.0 \
			--insecure-bind-address=0.0.0.0 \
	        	--etcd-servers=http://127.0.0.1:2379 \
			--admission-control=NamespaceLifecycle,LimitRanger,DefaultStorageClass,ResourceQuota \
			--service-cluster-ip-range=10.101.0.0/16 \
			--v=10 \
			--logtostderr=true

	# Wait until the apiserver is accepting requests.
	while ! docker exec st-apiserver kubectl get nodes; do echo "Waiting for apiserver to come up..."; sleep 2; done

	# And run the controller manager.
	docker run \
		--net=host --name st-controller-manager \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube kube-controller-manager \
                        --master=127.0.0.1:8080 \
                        --min-resync-period=3m \
                        --allocate-node-cidrs=true \
                        --cluster-cidr=10.10.0.0/16 \
                        --v=5

	# Create CustomResourceDefinition (CRD) for Calico resources
	# from the manifest crds.yaml
	docker run \
	    --net=host \
	    --rm \
		-v  $(CURDIR):/manifests \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube kubectl \
		--server=http://127.0.0.1:8080 \
		apply -f /manifests/test/crds.yaml

	# Create a Node in the API for the tests to use.
	docker run \
	    --net=host \
	    --rm \
		-v  $(CURDIR):/manifests \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube kubectl \
		--server=http://127.0.0.1:8080 \
		apply -f /manifests/test/mock-node.yaml

	# Create Namespaces required by namespaced Calico `NetworkPolicy`
	# tests from the manifests namespaces.yaml.
	docker run \
	    --net=host \
	    --rm \
		-v  $(CURDIR):/manifests \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube kubectl \
		--server=http://localhost:8080 \
		apply -f /manifests/test/namespaces.yaml

## Stop the local kubernetes master
stop-kubernetes-master:
	# Delete the cluster role binding.
	-docker exec st-apiserver kubectl delete clusterrolebinding anonymous-admin

	# Stop master components.
	-docker rm -f st-apiserver st-controller-manager

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
