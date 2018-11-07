###############################################################################
# The build architecture is select by setting the ARCH variable.
# For example: When building on ppc64le you could use ARCH=ppc64le make <....>.
# When ARCH is undefined it defaults to amd64.
ARCH?=amd64

ifeq ($(ARCH),amd64)
	ARCHTAG?=
	GO_BUILD_VER?=v0.8
endif

ifeq ($(ARCH),ppc64le)
	ARCHTAG:=-ppc64le
	GO_BUILD_VER?=latest
endif

# Disable make's implicit rules, which are not useful for golang, and slow down the build
# considerably.
.SUFFIXES:

all: clean test

CONTAINER_NAME?=calico/confd
GO_BUILD_CONTAINER?=calico/go-build$(ARCHTAG):$(GO_BUILD_VER)

K8S_VERSION=v1.7.4
ETCD_VER=v3.2.5
BIRD_VER=v0.3.1
LOCAL_IP_ENV?=$(shell ip route get 8.8.8.8 | head -1 | awk '{print $$7}')

CONFD_VERSION?=$(shell git describe --tags --dirty --always)
LDFLAGS=-ldflags "-X main.VERSION=$(CONFD_VERSION)"

# Ensure that the bin directory is always created
MAKE_SURE_BIN_EXIST := $(shell mkdir -p bin)

# All go files.
GO_FILES:=$(shell find . -type f -name '*.go')

# Figure out the users UID.  This is needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
MY_UID:=$(shell id -u)

DOCKER_GO_BUILD := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              $(EXTRA_DOCKER_ARGS) \
                              -e LOCAL_USER_ID=$(MY_UID) \
                              -v ${CURDIR}:/go/src/github.com/kelseyhightower/confd:rw \
                              -v ${CURDIR}/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/github.com/kelseyhightower/confd \
                              $(GO_BUILD_CONTAINER)

# Update the vendored dependencies with the latest upstream versions matching
# our glide.yaml.  If there are any changes, this updates glide.lock
# as a side effect.  Unless you're adding/updating a dependency, you probably
# want to use the vendor target to install the versions from glide.lock.
.PHONY: update-vendor
update-vendor:
	mkdir -p $$HOME/.glide
	$(DOCKER_GO_BUILD) glide up --strip-vendor
	touch vendor/.up-to-date

# vendor is a shortcut for force rebuilding the go vendor directory.
.PHONY: vendor
vendor vendor/.up-to-date: glide.lock
	mkdir -p $$HOME/.glide
	$(DOCKER_GO_BUILD) glide install --strip-vendor
	touch vendor/.up-to-date

.PHONY: image
image: container
container: bin/confd
	docker build -t $(CONTAINER_NAME) .

bin/confd: $(GO_FILES) vendor/.up-to-date
	@echo Building confd...
	$(DOCKER_GO_BUILD) \
	    sh -c 'go build -v -i -o $@ $(LDFLAGS) "github.com/kelseyhightower/confd" && \
		( ldd bin/confd 2>&1 | grep -q -e "Not a valid dynamic program" \
			-e "not a dynamic executable" || \
	             ( echo "Error: bin/confd was not statically linked"; false ) )'

## ensure we have a real IMAGETAG
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push images
push: imagetag
	docker push $(CONTAINER_NAME):$(IMAGETAG)
	docker push quay.io/$(CONTAINER_NAME):$(IMAGETAG)

## tag images
tag-images: imagetag
	docker tag $(CONTAINER_NAME):latest $(CONTAINER_NAME):$(IMAGETAG)
	docker tag $(CONTAINER_NAME):latest quay.io/$(CONTAINER_NAME):$(IMAGETAG)


###############################################################################
# CI
###############################################################################
.PHONY: ci
## Run all tests
ci: clean container test

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images push IMAGETAG=${BRANCH_NAME}
	$(MAKE) tag-images push IMAGETAG=$(shell git describe --tags --dirty --always --long)

.PHONY: test
## Run all tests
test: test-kdd test-etcd

.PHONY: test-kdd
## Run template tests against KDD
test-kdd: bin/confd bin/kubectl bin/bird bin/bird6 run-k8s-apiserver
	docker run --rm --net=host \
		-v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-e LOCAL_USER_ID=0 \
		$(GO_BUILD_CONTAINER) /tests/test_suite_kdd.sh

.PHONY: test-etcd
## Run template tests against etcd
test-etcd: bin/confd bin/etcdctl bin/bird bin/bird6 run-etcd
	docker run --rm --net=host \
		-v $(CURDIR)/tests/:/tests/ \
		-v $(CURDIR)/bin:/calico/bin/ \
		-e LOCAL_USER_ID=0 \
		$(GO_BUILD_CONTAINER) /tests/test_suite_etcd.sh

## Etcd is used by the kubernetes
run-etcd: stop-etcd
	docker run --detach \
	--net=host \
	--name calico-etcd quay.io/coreos/etcd:$(ETCD_VER)$(ARCHTAG) \
	etcd \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Stops calico-etcd containers
stop-etcd:
	@-docker rm -f calico-etcd

## Kubernetes apiserver used for tests
run-k8s-apiserver: stop-k8s-apiserver run-etcd
	docker run --detach --net=host \
	  --name calico-k8s-apiserver \
	gcr.io/google_containers/hyperkube-$(ARCH):$(K8S_VERSION) \
		  /hyperkube apiserver --etcd-servers=http://$(LOCAL_IP_ENV):2379 \
		  --service-cluster-ip-range=10.101.0.0/16 

## Stop Kubernetes apiserver
stop-k8s-apiserver:
	@-docker rm -f calico-k8s-apiserver

bin/kubectl:
	curl -sSf -L --retry 5 https://storage.googleapis.com/kubernetes-release/release/$(K8S_VERSION)/bin/linux/$(ARCH)/kubectl -o $@
	chmod +x $@

# If bird release is not available bin must be pre-populated with bird and bird6.
bin/bird:
	curl -sSf -L --retry 5 https://github.com/projectcalico/bird/releases/download/$(BIRD_VER)/bird -o $@
	chmod +x $@

bin/bird6:
	curl -sSf -L --retry 5 https://github.com/projectcalico/bird/releases/download/$(BIRD_VER)/bird6 -o $@
	chmod +x $@

bin/etcdctl:
	curl -sSf -L --retry 5  https://github.com/coreos/etcd/releases/download/$(ETCD_VER)/etcd-$(ETCD_VER)-linux-$(ARCH).tar.gz | tar -xz -C bin --strip-components=1 etcd-$(ETCD_VER)-linux-$(ARCH)/etcdctl 

bin/calicoctl:
	-docker rm -f calico/ctl
	# Latest calicoctl binaries are stored in automated builds of calico/ctl.
	# To get them, we create (but don't start) a container from that image.
	docker pull $(CALICOCTL_CONTAINER_NAME)
	docker create --name calico-ctl $(CALICOCTL_CONTAINER_NAME)
	# Then we copy the files out of the container.  Since docker preserves
	# mtimes on its copy, check the file really did appear, then touch it
	# to make sure that downstream targets get rebuilt.
	docker cp calico-ctl:/calicoctl $@ && \
	  test -e $@ && \
	  touch $@
	-docker rm -f calico-ctl

release: clean
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
	git tag $(VERSION)

	# Check to make sure the tag isn't "-dirty".
	if git describe --tags --dirty | grep dirty; \
	then echo current git working tree is "dirty". Make sure you do not have any uncommitted changes ;false; fi

	# Build binary and docker image. 
	$(MAKE) container 

	# Check that the version output includes the version specified.
	# Tests that the "git tag" makes it into the binaries. Main point is to catch "-dirty" builds
	# Release is currently supported on darwin / linux only.
	if ! docker run calico/confd /bin/confd --version | grep '$(VERSION)$$'; then \
	  echo "Reported version:" `docker run calico/confd /bin/confd --version` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

	# Retag images with corect version and quay
	docker tag calico/confd calico/confd:$(VERSION)
	docker tag calico/confd quay.io/calico/confd:$(VERSION)
	docker tag calico/confd quay.io/calico/confd:latest

	# Check that images were created recently and that the IDs of the versioned and latest images match
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" calico/confd 
	@docker images --format "{{.CreatedAt}}\tID:{{.ID}}\t{{.Repository}}:{{.Tag}}" calico/confd:$(VERSION)

	@echo ""
	@echo "# Push the created tag to GitHub"
	@echo "  git push origin $(VERSION)"
	@echo ""
	@echo "# Now, create a GitHub release from the tag, add release notes, and attach the following binaries:"
	@echo ""
	@echo "- bin/confd"
	@echo ""
	@echo "# To find commit messages for the release notes:  git log --oneline <old_release_version>...$(VERSION)"
	@echo ""
	@echo "# Now push the newly created release images."
	@echo ""
	@echo "  docker push calico/confd:$(VERSION)"
	@echo "  docker push quay.io/calico/confd:$(VERSION)"
	@echo ""
	@echo "# For the final release only, push the latest tag"
	@echo "# DO NOT PUSH THESE IMAGES FOR RELEASE CANDIDATES OR ALPHA RELEASES" 
	@echo ""
	@echo "  docker push calico/confd:latest"
	@echo "  docker push quay.io/calico/confd:latest"
	@echo ""
	@echo "See RELEASING.md for detailed instructions."

.PHONY: clean
clean:
	rm -rf bin/*
	rm -rf tests/logs
	-docker rmi -f calico/confd
	-docker rmi -f quay.io/calico/confd

