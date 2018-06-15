# Shortcut targets
default: build

## Build binary
all: build

## Run the tests
test: ut

# Define some constants
#######################
K8S_VERSION       = v1.8.1
GO_BUILD_VER     ?= v0.12
CALICO_BUILD     ?= calico/go-build:$(GO_BUILD_VER)
PACKAGE_NAME     ?= projectcalico/libcalico-go
LOCAL_USER_ID    ?= $(shell id -u $$USER)
BINDIR           ?= bin
LIBCALICO-GO_PKG  = github.com/projectcalico/libcalico-go
TOP_SRC_DIR       = lib
MY_UID           := $(shell id -u)

DOCKER_GO_BUILD := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              $(EXTRA_DOCKER_ARGS) \
                              -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
                              -v $(HOME)/.glide:/home/user/.glide:rw \
                              -v $(CURDIR):/go/src/github.com/$(PACKAGE_NAME):rw \
                              -v $(CURDIR)/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/github.com/$(PACKAGE_NAME) \
                              $(CALICO_BUILD)

# Create a list of files upon which the generated file depends, skip the generated file itself
UPGRADE_SRCS := $(filter-out ./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go, \
                             $(wildcard ./lib/upgrade/migrator/clients/v1/k8s/custom/*.go))

# Create a list of files upon which the generated file depends, skip the generated file itself
APIS_SRCS := $(filter-out ./lib/apis/v3/zz_generated.deepcopy.go, $(wildcard ./lib/apis/v3/*.go))

.PHONY: clean
## Removes all .coverprofile files, the vendor dir, and .go-pkg-cache
clean:
	find . -name '*.coverprofile' -type f -delete
	rm -rf vendor .go-pkg-cache
	rm -rf $(BINDIR)

.PHONY: clean-gen-files
## Convenience target for devs to remove generated files and related utilities
clean-gen-files:
	rm -f $(BINDIR)/deepcopy-gen
	rm -f ./lib/apis/v3/zz_generated.deepcopy.go
	rm -f ./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go

###############################################################################
# Building the binary
###############################################################################
# Build the vendor directory.
vendor: glide.lock
	# To build without Docker just run "glide install -strip-vendor"
	# Ensure that the glide cache directory exists.
	mkdir -p $(HOME)/.glide
	$(DOCKER_GO_BUILD) glide install --strip-vendor

.PHONY: gen-files
## Build generated-go utilities (e.g. deepcopy_gen) and generated files
gen-files: $(BINDIR)/deepcopy-gen \
           ./lib/apis/v3/zz_generated.deepcopy.go \
           ./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go

$(BINDIR)/deepcopy-gen: vendor
	$(DOCKER_GO_BUILD) \
		sh -c 'go build -o $@ $(LIBCALICO-GO_PKG)/vendor/k8s.io/code-generator/cmd/deepcopy-gen'

./lib/upgrade/migrator/clients/v1/k8s/custom/zz_generated.deepcopy.go: ${UPGRADE_SRCS}
	$(DOCKER_GO_BUILD) \
		sh -c '$(BINDIR)/deepcopy-gen \
			--v 1 --logtostderr \
			--go-header-file "./docs/boilerplate.go.txt" \
			--input-dirs "$(LIBCALICO-GO_PKG)/lib/upgrade/migrator/clients/v1/k8s/custom" \
			--bounding-dirs "github.com/projectcalico/libcalico-go" \
			--output-file-base zz_generated.deepcopy'

./lib/apis/v3/zz_generated.deepcopy.go: ${APIS_SRCS}
	$(DOCKER_GO_BUILD) \
		sh -c '$(BINDIR)/deepcopy-gen \
			--v 1 --logtostderr \
			--go-header-file "./docs/boilerplate.go.txt" \
			--input-dirs "$(LIBCALICO-GO_PKG)/lib/apis/v3" \
			--bounding-dirs "github.com/projectcalico/libcalico-go" \
			--output-file-base zz_generated.deepcopy'

###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
static-checks: check-format check-gen-files

.PHONY: check-gen-files
check-gen-files: gen-files
	git diff --exit-code || (echo "The generated targets changed, please 'make gen-files' and commit the results"; exit 1)

.PHONY: check-format
# Depends on the vendor directory because goimports needs to be able to resolve the imports.
check-format: vendor
	@if $(DOCKER_GO_BUILD) goimports -l lib | grep -v zz_generated | grep .; then \
	  echo "Some files in ./lib are not goimported"; \
	  false; \
	else \
	  echo "All files in ./lib are goimported"; \
	fi

.PHONY: goimports go-fmt format-code
# Format the code using goimports.  Depends on the vendor directory because goimports needs
# to be able to resolve the imports.
goimports go-fmt format-code fix: vendor
	$(DOCKER_GO_BUILD) goimports -w lib

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks

###############################################################################
# Tests
###############################################################################
.PHONY: ut-cover
## Run the UTs natively with code coverage.  This requires a local etcd and local kubernetes master to be running.
ut-cover: vendor
	./run-uts

.PHONY:ut
## Run the tests in a container. Useful for CI, Mac dev.
ut: vendor run-etcd run-kubernetes-master
	-mkdir -p .go-pkg-cache
	docker run --rm -t --privileged --net=host \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    -v $(CURDIR):/go/src/github.com/$(PACKAGE_NAME):rw \
    -v $(CURDIR)/.go-pkg-cache:/go-cache/:rw \
    -e GOCACHE=/go-cache \
    $(CALICO_BUILD) sh -c 'cd /go/src/github.com/$(PACKAGE_NAME) && ginkgo -r --skipPackage vendor .'

## Run etcd as a container (calico-etcd)
run-etcd: stop-etcd
	docker run --detach \
	--net=host \
	--entrypoint=/usr/local/bin/etcd \
	--name calico-etcd quay.io/coreos/etcd:v3.1.7 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Run a local kubernetes master with API via hyperkube
run-kubernetes-master: stop-kubernetes-master
	# Run a Kubernetes apiserver using Docker.
	docker run \
		--net=host --name st-apiserver \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube apiserver \
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
		/hyperkube controller-manager \
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
		lachlanevenson/k8s-kubectl:${K8S_VERSION} \
		--server=http://127.0.0.1:8080 \
		apply -f manifests/test/crds.yaml

	# Create a Node in the API for the tests to use.
	docker run \
	    --net=host \
	    --rm \
		-v  $(CURDIR):/manifests \
		lachlanevenson/k8s-kubectl:${K8S_VERSION} \
		--server=http://127.0.0.1:8080 \
		apply -f manifests/test/mock-node.yaml

	# Create Namespaces required by namespaced Calico `NetworkPolicy`
	# tests from the manifests namespaces.yaml.
	docker run \
	    --net=host \
	    --rm \
		-v  $(CURDIR):/manifests \
		lachlanevenson/k8s-kubectl:${K8S_VERSION} \
		--server=http://localhost:8080 \
		apply -f manifests/test/namespaces.yaml

## Stop the local kubernetes master
stop-kubernetes-master:
	# Delete the cluster role binding.
	-docker exec st-apiserver kubectl delete clusterrolebinding anonymous-admin

	# Stop master components.
	-docker rm -f st-apiserver st-controller-manager

## Stop the etcd container (calico-etcd)
stop-etcd:
	-docker rm -f calico-etcd

###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean static-checks test


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
	width=23                                                            \
	$(MAKEFILE_LIST)