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
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix protobuf
	rm app-policy/proto/*.pb.go
	$(MAKE) -C app-policy proto

fix:
	$(MAKE) -C api fix
	$(MAKE) -C apiserver fix
	$(MAKE) -C app-policy fix
	$(MAKE) -C calicoctl fix
	$(MAKE) -C cni-plugin fix
	$(MAKE) -C confd fix
	$(MAKE) -C felix fix
	$(MAKE) -C kube-controllers fix
	$(MAKE) -C libcalico-go fix
	$(MAKE) -C node fix
	$(MAKE) -C pod2daemon fix
	$(MAKE) -C typha fix

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
