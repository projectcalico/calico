.PHONY: all test

default: all
all: test
test: ut

K8S_VERSION=1.6.3
CALICO_BUILD?=calico/go-build
PACKAGE_NAME?=projectcalico/libcalico-go
LOCAL_USER_ID?=$(shell id -u $$USER)

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
	# Run the kubelet which will launch the master components in a pod.
	docker run \
                 -v /proc:/rootfs/proc:ro \
                 -v /sys:/sys:ro \
                 -v /var/run:/var/run:rw \
                 -v /var/lib/docker/:/var/lib/docker:rw \
                 -v /var/lib/kubelet/:/var/lib/kubelet:rw \
                 -v ${PWD}/kubernetes-manifests:/etc/kubernetes/:rw \
                 --net=host \
                 --pid=host \
                 --privileged=true \
                 --name calico-kubelet-master \
                 -d \
                 gcr.io/google_containers/hyperkube-amd64:v${K8S_VERSION} \
                 /hyperkube kubelet \
                 	--containerized \
                 	--hostname-override="127.0.0.1" \
                 	--address="0.0.0.0" \
                 	--api-servers=http://localhost:8080 \
	                --pod-manifest-path=/etc/kubernetes/manifests-multi/ \
                 	--cluster-dns=10.0.0.10 \
                 	--cluster-domain=cluster.local \
	                --allow-privileged=true --v=2 \
			--cgroups-per-qos=false --enforce-node-allocatable=""
	# Wait until the newly launched API server can respond to a
	# request on port 8080, before completing this Makefile
	# target.
	docker run \
		--rm \
		--net=host \
		tutum/curl \
		sh -c "while ! curl http://localhost:8080/apis/extensions/v1beta1/thirdpartyresources; do sleep 2; done"

## Stop the local kubernetes master
stop-kubernetes-master:
	# Stop any existing kubelet that we started
	-docker rm -f calico-kubelet-master

	# Remove any pods that the old kubelet may have started.
	-docker ps -af name=k8s_ | awk 'NR < 2 {next}{print $$1}' | while read x;do docker rm -f $$x;done

	# Remove any left over volumes
	-docker volume ls -qf dangling=true | while read x;do docker volume rm $$x;done
	-mount | grep kubelet | awk '{print $$3}' | while read x;do umount $$x;done

## Stop the etcd container (calico-etcd)
stop-etcd:
	-docker rm -f calico-etcd

.PHONY: clean
## Removes all .coverprofile files, the vendor dir, and .go-pkg-cache
clean:
	find . -name '*.coverprofile' -type f -delete
	rm -rf vendor .go-pkg-cache

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
