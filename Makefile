
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

deb: calico-build/trusty calico-build/xenial calico-build/bionic networking-calico
	cd networking-calico && ../utils/make-packages.sh deb

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

networking-calico:
	git clone https://opendev.org/openstack/networking-calico.git
