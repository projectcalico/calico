###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=amd64 arm64 ppc64le s390x

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)

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

GO_BUILD_VER ?= v0.15



# Disable make's implicit rules, which are not useful for golang, and slow down the build
# considerably.
.SUFFIXES:

SRCFILES=calico.go $(wildcard utils/*.go) $(wildcard k8s/*.go) ipam/calico-ipam.go
TEST_SRCFILES=$(wildcard test_utils/*.go) $(wildcard calico_cni_*.go)
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

# fail if unable to download
CURL=curl -sSf

K8S_VERSION=1.6.1
CNI_VERSION=v0.6.0

# Get version from git.
GIT_VERSION?=$(shell git describe --tags --dirty)

# By default set the CNI_SPEC_VERSION to 0.3.1 for tests.
CNI_SPEC_VERSION?=0.3.1

DIST=dist/$(ARCH)
# Ensure that the dist directory is always created
MAKE_SURE_DIST_EXIST := $(shell mkdir -p $(DIST))
CALICO_BUILD?=calico/go-build:$(GO_BUILD_VER)
CONTAINER_NAME=calico/cni
DEPLOY_CONTAINER_MARKER=cni_deploy_container-$(ARCH).created

ETCD_CONTAINER ?= quay.io/coreos/etcd:v3.2.5-$(BUILDARCH)
# If building on amd64 omit the arch in the container name.
ifeq ($(BUILDARCH),amd64)
        ETCD_CONTAINER=quay.io/coreos/etcd:v3.2.5
endif

LIBCALICOGO_PATH?=none

DATASTORE_TYPE?=etcdv3

LOCAL_USER_ID?=$(shell id -u $$USER)

.PHONY: all binary plugin ipam image image-all
default: all
all: vendor build-containerized test-containerized
binary:  plugin ipam
plugin: $(DIST)/calico
ipam: $(DIST)/calico-ipam
image: $(DEPLOY_CONTAINER_MARKER)
image-all: $(addprefix sub-image-,$(ARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*


.PHONY: clean
clean:
	rm -rf $(DIST) vendor $(DEPLOY_CONTAINER_MARKER) .go-pkg-cache k8s-install/scripts/install_cni.test


###############################################################################
# tag and push images of any tag
###############################################################################


# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## push all archs
push-all: imagetag $(addprefix sub-push-,$(ARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)


## tag images of one arch
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)-$(ARCH)
ifeq ($(ARCH),amd64)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest-$(ARCH) quay.io/$(CONTAINER_NAME):$(IMAGETAG)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(ARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)



###############################################################################

###############################################################################
# Release targets
###############################################################################
PREVIOUS_RELEASE=$(shell git describe --tags --abbrev=0)

## Tags and builds a release from start to finish.
release: release-prereqs
	$(MAKE) VERSION=$(VERSION) release-tag
	$(MAKE) VERSION=$(VERSION) release-build
	$(MAKE) VERSION=$(VERSION) release-verify

	@echo ""
	@echo "Release build complete. Next, push the produced images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish"
	@echo ""

## Produces a git tag for the release.
release-tag: release-prereqs release-notes
	git tag $(VERSION) -F release-notes-$(VERSION)
	@echo ""
	@echo "Now you can build the release:"
	@echo ""
	@echo "  make VERSION=$(VERSION) release-build"
	@echo ""

## Produces a clean build of release artifacts at the specified version.
release-build: release-prereqs clean
# Check that the correct code is checked out.
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif
	$(MAKE) image
	$(MAKE) tag-images IMAGETAG=$(VERSION)
	$(MAKE) tag-images IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	docker run --rm calico/cni:$(VERSION)-$(ARCH) calico -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm calico/cni:$(VERSION)-$(ARCH) calico -v` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/calico/cni:$(VERSION)-$(ARCH) calico-ipam -v | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )

	# TODO: Some sort of quick validation of the produced binaries.

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	# Push images.
	$(MAKE) push IMAGETAG=$(VERSION) ARCH=$(ARCH)

	# Push GCR images.
	docker push gcr.io/projectcalico-org/cni:$(ARCHTAG):$(VERSION)
	docker push eu.gcr.io/projectcalico-org/cni:$(ARCHTAG):$(VERSION)
	docker push asia.gcr.io/projectcalico-org/cni:$(ARCHTAG):$(VERSION)
	docker push us.gcr.io/projectcalico-org/cni:$(ARCHTAG):$(VERSION)

	@echo "Finalize the GitHub release based on the pushed tag."
	@echo "Attach the $(DIST)/calico and $(DIST)/calico-ipam binaries."
	@echo ""
	@echo "  https://github.com/projectcalico/cni-plugin/releases/tag/$(VERSION)"
	@echo ""
	@echo "If this is the latest stable release, then run the following to push 'latest' images."
	@echo ""
	@echo "  make VERSION=$(VERSION) release-publish-latest"
	@echo ""

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(CONTAINER_NAME):latest-$(ARCH) calico -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(CONTAINER_NAME):latest-$(ARCH) calico -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(CONTAINER_NAME):latest-$(ARCH) calico -v | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(CONTAINER_NAME):latest-$(ARCH) calico -v` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push IMAGETAG=latest ARCH=$(ARCH)

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif

# To update upstream dependencies, delete the glide.lock file first.
## Use this to populate the vendor directory after checking out the repository.
vendor: glide.yaml
	# To build without Docker just run "glide install -strip-vendor"
	-mkdir -p ~/.glide
	if [ "$(LIBCALICOGO_PATH)" != "none"  ]; then \
	  EXTRA_DOCKER_BIND="-v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro"; \
	fi; \
	docker run --rm \
	  -v $(CURDIR):/go/src/github.com/projectcalico/cni-plugin:rw $$EXTRA_DOCKER_BIND \
		-v $(HOME)/.glide:/home/user/.glide:rw \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		$(CALICO_BUILD) /bin/sh -c ' \
			cd /go/src/github.com/projectcalico/cni-plugin && \
			glide install -strip-vendor'

## Build the Calico network plugin
$(DIST)/calico: $(SRCFILES) vendor
	mkdir -p $(@D)
	CGO_ENABLED=0 GOARCH=$(ARCH) go build -v -i -o $(DIST)/calico \
	-ldflags "-X main.VERSION=$(GIT_VERSION) -s -w" calico.go

## Build the Calico ipam plugin
$(DIST)/calico-ipam: $(SRCFILES) vendor
	mkdir -p $(@D)
	CGO_ENABLED=0 GOARCH=$(ARCH) go build -v -i -o $(DIST)/calico-ipam  \
	-ldflags "-X main.VERSION=$(GIT_VERSION) -s -w" ipam/calico-ipam.go

.PHONY: test
## Run the unit tests.
test: $(DIST)/calico $(DIST)/calico-ipam $(DIST)/host-local run-etcd run-k8s-apiserver test-install-cni
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo)

.PHONY: test-watch
## Run the unit tests, watching for changes.
test-watch: $(DIST)/calico $(DIST)/calico-ipam run-etcd run-k8s-apiserver
	# The tests need to run as root
	sudo CGO_ENABLED=0 ETCD_IP=127.0.0.1 PLUGIN=calico GOPATH=$(GOPATH) $(shell which ginkgo) watch

$(DEPLOY_CONTAINER_MARKER): Dockerfile.$(ARCH) build-containerized fetch-cni-bins
	docker build -f Dockerfile.$(ARCH) -t $(CONTAINER_NAME):latest-$(ARCH) .
ifeq ($(ARCH),amd64)
	# Need amd64 builds tagged as :latest because Semaphore depends on that
	docker tag $(CONTAINER_NAME):latest-$(ARCH) $(CONTAINER_NAME):latest
endif
	touch $@

.PHONY: fetch-cni-bins
fetch-cni-bins: $(DIST)/flannel $(DIST)/loopback $(DIST)/host-local $(DIST)/portmap

$(DIST)/flannel $(DIST)/loopback $(DIST)/host-local $(DIST)/portmap:
	mkdir -p $(DIST)
	$(CURL) -L --retry 5 https://github.com/containernetworking/plugins/releases/download/$(CNI_VERSION)/cni-plugins-$(ARCH)-$(CNI_VERSION).tgz | tar -xz -C $(DIST) ./flannel ./loopback ./host-local ./portmap

# Useful for CI but currently slow for local development because the
# .go-pkg-cache can't be used (since tests run as root)
.PHONY: test-containerized
## Run the tests in a container (as root)
test-containerized: run-etcd run-k8s-apiserver build-containerized $(DIST)/host-local
	docker run --rm --privileged --net=host \
	-e ETCD_IP=$(LOCAL_IP_ENV) \
	-e LOCAL_USER_ID=0 \
	-e ARCH=$(ARCH) \
	-e PLUGIN=calico \
	-e DIST=$(DIST) \
	-e CNI_SPEC_VERSION=$(CNI_SPEC_VERSION) \
	-e DATASTORE_TYPE=$(DATASTORE_TYPE) \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-v $(CURDIR):/go/src/github.com/projectcalico/cni-plugin:rw \
	$(CALICO_BUILD) sh -c '\
			cd  /go/src/github.com/projectcalico/cni-plugin && \
			make run-tests'
	make stop-etcd

# This does not currently work, kubernetes needs additional configuration
# before the tests will run correctly.
.PHONY: test-containerized-all-datastore
test-containerized-all-datastore:
	for datastore in "etcdv3" "kubernetes" ; do \
		make test-containerized DATASTORE_TYPE=$$datastore; \
	done

# We pre-build the test binary so that we can run it outside a container and allow it
# to interact with docker.
k8s-install/scripts/install_cni.test: vendor
	-mkdir -p .go-pkg-cache
	docker run --rm \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-v $(CURDIR):/go/src/github.com/projectcalico/cni-plugin:rw \
	-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/github.com/projectcalico/cni-plugin && \
			go test ./k8s-install/scripts -c --tags install_cni_test -o ./k8s-install/scripts/install_cni.test'

.PHONY: test-install-cni
## Test the install-cni.sh script
test-install-cni: image k8s-install/scripts/install_cni.test
	cd k8s-install/scripts && CONTAINER_NAME=$(CONTAINER_NAME) ./install_cni.test

run-test-containerized-without-building: run-etcd run-k8s-apiserver
	docker run --rm --privileged --net=host \
	-e ETCD_IP=$(LOCAL_IP_ENV) \
	-e LOCAL_USER_ID=0 \
	-e ARCH=$(ARCH) \
	-e PLUGIN=calico \
	-e DIST=$(DIST) \
	-e CNI_SPEC_VERSION=$(CNI_SPEC_VERSION) \
	-e DATASTORE_TYPE=$(DATASTORE_TYPE) \
	-e ETCD_ENDPOINTS=http://$(LOCAL_IP_ENV):2379 \
	-v $(CURDIR):/go/src/github.com/projectcalico/cni-plugin:rw \
	$(CALICO_BUILD) sh -c '\
			cd  /go/src/github.com/projectcalico/cni-plugin && \
			make run-tests'
	make stop-etcd

## Run the tests in a container (as root) for different CNI spec versions
## to make sure we don't break backwards compatibility.
.PHONY: test-containerized-cni-versions
test-containerized-cni-versions: build-containerized $(DIST)/host-local;
	for cniversion in "0.2.0" "0.3.1" ; do \
		make run-test-containerized-without-building CNI_SPEC_VERSION=$$cniversion; \
	done

.PHONY: build-containerized build
## Run the build in a container. Useful for CI
build: build-containerized
build-containerized: vendor
	-mkdir -p $(DIST)
	-mkdir -p .go-pkg-cache
	docker run --rm \
	-e ARCH=$(ARCH) \
	-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	-v $(CURDIR):/go/src/github.com/projectcalico/cni-plugin:ro \
	-v $(CURDIR)/$(DIST):/go/src/github.com/projectcalico/cni-plugin/$(DIST) \
	-v $(CURDIR)/.go-pkg-cache:/go/pkg/:rw \
		$(CALICO_BUILD) sh -c '\
			cd /go/src/github.com/projectcalico/cni-plugin && \
			make binary'

.PHONY: run-tests
## Run the tests locally, must have local etcd running
run-tests:
	# Run tests recursively (-r).
	ginkgo -cover -r -skipPackage vendor -skipPackage k8s-install

	@echo
	@echo '+==============+'
	@echo '| All coverage |'
	@echo '+==============+'
	@echo
	@find . -iname '*.coverprofile' | xargs -I _ go tool cover -func=_

	@echo
	@echo '+==================+'
	@echo '| Missing coverage |'
	@echo '+==================+'
	@echo
	@find . -iname '*.coverprofile' | xargs -I _ go tool cover -func=_ | grep -v '100.0%'

## Etcd is used by the tests
run-etcd: stop-etcd
	docker run --detach \
	-p 2379:2379 \
	--name calico-etcd $(ETCD_CONTAINER) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Etcd is used by the kubernetes
run-etcd-host: stop-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd $(ETCD_CONTAINER) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Stops calico-etcd containers
stop-etcd:
	@-docker rm -f calico-etcd

## Kubernetes apiserver used for tests
run-k8s-apiserver: stop-k8s-apiserver
	docker run --detach --net=host \
	  --name calico-k8s-apiserver \
  	gcr.io/google_containers/hyperkube-$(ARCH):v$(K8S_VERSION) \
		  /hyperkube apiserver --etcd-servers=http://$(LOCAL_IP_ENV):2379 \
		  --service-cluster-ip-range=10.101.0.0/16

## Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f calico-k8s-apiserver

.PHONY: static-checks
## Perform static checks on the code. The golint checks are allowed to fail, the others must pass.
static-checks: vendor
	docker run --rm \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-v $(CURDIR):/go/src/github.com/projectcalico/cni-plugin \
		$(CALICO_BUILD) sh -c '\
			cd  /go/src/github.com/projectcalico/cni-plugin && \
			gometalinter --deadline=300s --disable-all --enable=goimports --enable=vet --enable=errcheck --vendor -s test_utils ./...'

install:
	CGO_ENABLED=0 go install github.com/projectcalico/cni-plugin

## Retrieve an old version of the Python CNI plugin for use in tests
$(DIST)/calico-python:
	$(CURL) -L https://github.com/projectcalico/cni-plugin/releases/download/v1.3.1/calico -o $@
	chmod +x $@

## Retrieve an old version of the Python CNI plugin for use in tests
$(DIST)/calico-ipam-python:
	$(CURL) -L https://github.com/projectcalico/cni-plugin/releases/download/v1.3.1/calico-ipam -o $@
	chmod +x $@

# Copy the plugin into place
deploy-rkt: binary
	cp $(DIST)/calico /etc/rkt/net.d
	cp $(DIST)/calico-ipam /etc/rkt/net.d
	echo '{"name": "prod","log_level":"warning","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"host-local","subnet": "10.10.0.0/8"}}' >/etc/rkt/net.d/calico-warning.conf
	echo '{"name": "mtu","mtu":999,"type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"host-local","subnet": "10.10.0.0/8"}}' >/etc/rkt/net.d/calico-mtu.conf
	echo '{"name": "dev", "log_level":"info","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"calico-ipam"}}' >/etc/rkt/net.d/calico-info.conf
	echo '{"name": "debug", "log_level":"debug","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"calico-ipam"}}' >/etc/rkt/net.d/calico-debug.conf
	echo '{"name": "ipv6", "log_level":"info","type":"calico","etcd_authority":"127.0.0.1:2379","ipam":{"type":"calico-ipam", "assign_ipv6":"true"}}' >/etc/rkt/net.d/calico-ipv6.conf
	echo '{"name": "secure", "log_level":"debug","type":"calico","etcd_endpoints":"https://etcd-authority-ssl:2379","etcd_key_file":"/etc/calico/client-key.pem","etcd_cert_file":"/etc/calico/client.pem","etcd_ca_cert_file":"/etc/calico/ca.pem", "ipam":{"type":"calico-ipam"}}' >/etc/rkt/net.d/calico-secure.conf
	@echo ""
	@echo Now create containers using rkt e.g.
	@echo sudo rkt run quay.io/coreos/alpine-sh --exec ifconfig --net=prod
	@echo sudo rkt run quay.io/coreos/alpine-sh --exec ifconfig --net=dev
	@echo sudo rkt run quay.io/coreos/alpine-sh --exec ifconfig --net=prod --net=dev

## Run kubernetes master
run-kubernetes-master: stop-kubernetes-master run-etcd-host binary
	echo Get kubectl from http://storage.googleapis.com/kubernetes-release/release/v$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl
	mkdir -p net.d
	#echo '{"name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
	#echo '{"log_level":"DEBUG", "name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "10.101.0.0/16"}}' >net.d/10-calico.conf
	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1", "kubeconfig":"/etc/cni/net.d/kubeconfig"}, "policy": {"type": "k8s"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
#	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"k8s_insecure_skip_tls_verify":true,"type": "k8s", "k8s_api_root":"https://10.7.50.75:6443", "k8s_auth_token":"YcFKOZdGR2c1XagRzhT6E5dHjNlbzmO9"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
#	echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "kubernetes":{"node_name":"127.0.0.1"}, "policy": {"k8s_insecure_skip_tls_verify":true,"type": "k8s", "k8s_api_root":"https://10.7.50.75:6443", "k8s_username":"admin", "k8s_password":"admin"},"ipam": {"type": "host-local", "subnet": "usePodCidr"}}' >net.d/10-calico.conf
	#echo '{"log_level":"DEBUG","name": "k8s","type": "calico","etcd_authority": "${LOCAL_IP_ENV}:2379", "ipam": {"type": "host-local", "subnet": "10.13.0.0/16"}}' >net.d/10-calico.conf

	# Run the kubelet which will launch the master components in a pod.
	docker run \
		--volume=/:/rootfs:ro \
		--volume=/sys:/sys:ro \
		--volume=/var/lib/docker/:/var/lib/docker:rw \
		--volume=/var/lib/kubelet/:/var/lib/kubelet:rw \
		--volume=`pwd`/$(DIST):/opt/cni/bin \
		--volume=`pwd`/net.d:/etc/cni/net.d \
		--volume=/var/run:/var/run:rw \
		--net=host \
		--pid=host \
		--privileged=true \
		--name calico-kubelet-master \
		-d \
		gcr.io/google_containers/hyperkube-$(ARCH):v${K8S_VERSION} \
		/hyperkube kubelet \
			--containerized \
			--hostname-override="127.0.0.1" \
			--address="0.0.0.0" \
			--api-servers=http://localhost:8080 \
			--config=/etc/kubernetes/manifests-multi \
			--cluster-dns=10.0.0.10 \
			--network-plugin=cni \
			--network-plugin-dir=/etc/cni/net.d \
			--cluster-domain=cluster.local \
			--allow-privileged=true --v=2

	@echo "Now manually start a calico-node container"

## Stop kubernetes master
stop-kubernetes-master:
	# Stop any existing kubelet that we started
	-docker rm -f calico-kubelet-master

	# Remove any pods that the old kubelet may have started.
	-docker rm -f $$(docker ps | grep k8s_ | awk '{print $$1}')

	# Remove any left over volumes
	-docker volume ls -qf dangling=true | xargs -r docker volume rm
	-mount |grep kubelet | awk '{print $$3}' |sudo xargs umount

## Run kube-proxy
run-kube-proxy:
	-docker rm -f calico-kube-proxy
	docker run --name calico-kube-proxy -d --net=host --privileged gcr.io/google_containers/hyperkube:v$(K8S_VERSION) /hyperkube proxy --master=http://127.0.0.1:8080 --v=2

ci: clean static-checks test-containerized-cni-versions image test-install-cni

.PHONY: help
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
