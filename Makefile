PACKAGE_NAME = github.com/projectcalico/calico

include metadata.mk 
include lib.Makefile


DOCKER_RUN := mkdir -p ../.go-pkg-cache bin $(GOMOD_CACHE) && \
	docker run --rm \
		--net=host \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		$(GOARCH_FLAGS) \
		-e GOPATH=/go \
		-e OS=$(BUILDOS) \
		-e GOOS=$(BUILDOS) \
		-e GOFLAGS=$(GOFLAGS) \
		-v $(CURDIR):/go/src/github.com/projectcalico/calico:rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

MAKE_DIRS=$(shell ls -d */)

generate:
	make -C api gen-files 
	make -C libcalico-go gen-files

# Build all Calico images for all architectures.
image-all: image
	$(MAKE) -C pod2daemon image-all
	$(MAKE) -C calicoctl image-all
	$(MAKE) -C cni-plugin image-all
	$(MAKE) -C apiserver image-all
	$(MAKE) -C kube-controllers image-all
	$(MAKE) -C app-policy image-all
	$(MAKE) -C typha image-all
	$(MAKE) -C node image-all

# Build all Calico images for the current architecture.
image:
	$(MAKE) -C pod2daemon image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C calicoctl image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C app-policy image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

cd:
	$(MAKE) -C pod2daemon cd CONFIRM=$(CONFIRM)
	$(MAKE) -C calicoctl cd CONFIRM=$(CONFIRM)
	$(MAKE) -C cni-plugin cd CONFIRM=$(CONFIRM)
	$(MAKE) -C apiserver cd CONFIRM=$(CONFIRM)
	$(MAKE) -C kube-controllers cd CONFIRM=$(CONFIRM)
	$(MAKE) -C app-policy cd CONFIRM=$(CONFIRM)
	$(MAKE) -C typha cd CONFIRM=$(CONFIRM)
	$(MAKE) -C node cd CONFIRM=$(CONFIRM)
