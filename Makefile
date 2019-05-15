
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

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
LOCAL_USER_ID:=$(shell id -u)
LOCAL_GROUP_ID:=$(shell id -g)

deb: calico-build/trusty calico-build/xenial calico-build/bionic networking-calico
	cd networking-calico && ../utils/make-packages.sh deb

rpm: calico-build/centos7 networking-calico
	cd networking-calico && ../utils/make-packages.sh rpm

# Build a docker image used for building debs for trusty.
.PHONY: calico-build/trusty
calico-build/trusty:
	cd docker-build-images && docker build -f ubuntu-trusty-build.Dockerfile.$(ARCH) -t calico-build/trusty .

# Build a docker image used for building debs for xenial.
.PHONY: calico-build/xenial
calico-build/xenial:
	cd docker-build-images && docker build -f ubuntu-xenial-build.Dockerfile.$(ARCH) -t calico-build/xenial .

# Build a docker image used for building debs for bionic.
.PHONY: calico-build/bionic
calico-build/bionic:
	cd docker-build-images && docker build -f ubuntu-bionic-build.Dockerfile.$(ARCH) -t calico-build/bionic .

# Construct a docker image for building Centos 7 RPMs.
.PHONY: calico-build/centos7
calico-build/centos7:
	cd docker-build-images && \
	  docker build \
	  --build-arg=UID=$(LOCAL_USER_ID) \
	  --build-arg=GID=$(LOCAL_GROUP_ID) \
	  -f centos7-build.Dockerfile.$(ARCH) \
	  -t calico-build/centos7 .

ifeq ("$(ARCH)","ppc64le")
	# Some commands that would typically be run at container build time must be run in a privileged container.
	@-docker rm -f centos7Tmp
	docker run --privileged --name=centos7Tmp calico-build/centos7 \
		/bin/bash -c "/setup-user; /install-centos-build-deps"
	docker commit centos7Tmp calico-build/centos7:latest
endif

NETWORKING_CALICO_REPO?=https://opendev.org/openstack/networking-calico.git
NETWORKING_CALICO_CHECKOUT?=master

networking-calico:
	git clone $(NETWORKING_CALICO_REPO)
	cd networking-calico && git checkout $(NETWORKING_CALICO_CHECKOUT)
