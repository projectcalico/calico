.PHONY: all test

default: all
all: test
test: ut
deepcopy-gen: .deepcopy_gen

# Define some constants
#######################
K8S_VERSION       = v1.8.1
CALICO_BUILD     ?= calico/go-build:v0.9
PACKAGE_NAME     ?= projectcalico/libcalico-go
LOCAL_USER_ID    ?= $(shell id -u $$USER)
BINDIR           ?= bin
LIBCALICO-GO_PKG  = github.com/projectcalico/libcalico-go
TOP_SRC_DIR       = lib
MY_UID           := $(shell id -u)

## Use this to populate the vendor directory after checking out the repository.
vendor: glide.yaml
	# To update upstream dependencies, delete the glide.lock file first.
	# To build without Docker just run "glide install -strip-vendor"
	docker run --rm \
    -v $(CURDIR):/go/src/github.com/$(PACKAGE_NAME):rw \
    -v $(HOME)/.glide:/home/user/.glide:rw \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    $(CALICO_BUILD) /bin/sh -c ' \
		  cd /go/src/github.com/$(PACKAGE_NAME) && \
      glide install --strip-vendor'

.PHONY: ut
## Run the UTs locally.  This requires a local etcd and local kubernetes master to be running.
ut: vendor
	./run-uts

.PHONY: test-containerized
## Run the tests in a container. Useful for CI, Mac dev.
test-containerized: vendor run-etcd run-kubernetes-master
	-mkdir -p .go-pkg-cache
	docker run --rm --privileged --net=host \
    -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
    -v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
    -v $(CURDIR):/go/src/github.com/$(PACKAGE_NAME):rw \
    $(CALICO_BUILD) sh -c 'cd /go/src/github.com/$(PACKAGE_NAME) && make WHAT=$(WHAT) SKIP=$(SKIP) ut'

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
			--authorization-mode=RBAC \
			--service-cluster-ip-range=10.101.0.0/16 \
			--v=10 \
			--logtostderr=true

	# Wait until we can configure a cluster role binding which allows anonymous auth.
	while ! docker exec st-apiserver kubectl create clusterrolebinding anonymous-admin --clusterrole=cluster-admin --user=system:anonymous; do echo "Trying to create ClusterRoleBinding"; sleep 2; done

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

.PHONY: clean
## Removes all .coverprofile files, the vendor dir, and .go-pkg-cache
clean: clean-deepcopy-gen clean-bin
	find . -name '*.coverprofile' -type f -delete
	rm -rf vendor .go-pkg-cache

clean-deepcopy-gen:
	rm -f .deepcopy_gen
	find $(TOP_SRC_DIR) -name zz_generated* -exec rm {} \;

clean-bin:
	rm -rf $(BINDIR) .deepcopy_gen_exes

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

DOCKER_GO_BUILD := \
	mkdir -p .go-pkg-cache && \
	docker run --rm \
		--net=host \
		$(EXTRA_DOCKER_ARGS) \
		-e LOCAL_USER_ID=$(MY_UID) \
		-v $${PWD}:/go/src/github.com/projectcalico/libcalico-go \
		-v $${PWD}/.go-pkg-cache:/go/pkg:rw \
		-w /go/src/github.com/projectcalico/libcalico-go \
		$(CALICO_BUILD)

.deepcopy_gen_exes: $(BINDIR)/deepcopy-gen
	touch $@

$(BINDIR)/deepcopy-gen:
	$(DOCKER_GO_BUILD) \
		sh -c 'go build -o $@ $(LIBCALICO-GO_PKG)/vendor/k8s.io/code-generator/cmd/deepcopy-gen'

# Regenerate all files if the gen exe(s) changed
.deepcopy_gen: .deepcopy_gen_exes
	# Generate deep copies
	$(DOCKER_GO_BUILD) \
		sh -c '$(BINDIR)/deepcopy-gen \
			--v 1 --logtostderr \
			--go-header-file "./docs/boilerplate.go.txt" \
			--input-dirs "$(LIBCALICO-GO_PKG)/lib/apis/v3" \
			--bounding-dirs "github.com/projectcalico/libcalico-go" \
			--output-file-base zz_generated.deepcopy'
