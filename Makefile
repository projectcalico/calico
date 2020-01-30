# This Makefile builds Felix and releases it in various forms:
#
#				   Go install
#				      Glide
#					|
#					|
#					|
#		 +-------+	      v
#		 | Felix |   +---------------------+
#		 |  Go   |   | calico/go-build     |
#		 |  code |   +---------------------+
#		 +-------+	 /
#			\	 /
#			 \       /
#			  \     /
#			  go build
#			      \
#			       \
#				\
#				 :
#				 v
#		       +------------------+
#		       | bin/calico-felix |
#		       +------------------+
#				 /
#				/
#			       /
#		      .-------'
#		     /
#		    /
#		   /
#		  /
#	    docker build
#		  |
#		  |
#		  |
#		  v
#	   +--------------+
#	   | calico/felix |
#	   +--------------+
#
###############################################################################

# Disable built-in rules
.SUFFIXES:

# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut fv

###############################################################################
# Both native and cross architecture builds are supported.
# The target architecture is select by setting the ARCH variable.
# When ARCH is undefined it is set to the detected host architecture.
# When ARCH differs from the host architecture a crossbuild will be performed.
ARCHES=$(patsubst docker-image/Dockerfile.%,%,$(wildcard docker-image/Dockerfile.*))

# BUILDARCH is the host architecture
# ARCH is the target architecture
# we need to keep track of them separately
BUILDARCH ?= $(shell uname -m)
BUILDOS ?= $(shell uname -s | tr A-Z a-z)

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

# we want to be able to run the same recipe on multiple targets keyed on the image name
# to do that, we would use the entire image name, e.g. calico/node:abcdefg, as the stem, or '%', in the target
# however, make does **not** allow the usage of invalid filename characters - like / and : - in a stem, and thus errors out
# to get around that, we "escape" those characters by converting all : to --- and all / to ___ , so that we can use them
# in the target, we then unescape them back
escapefs = $(subst :,---,$(subst /,___,$(1)))
unescapefs = $(subst ---,:,$(subst ___,/,$(1)))

# these macros create a list of valid architectures for pushing manifests
space :=
space +=
comma := ,
prefix_linux = $(addprefix linux/,$(strip $1))
join_platforms = $(subst $(space),$(comma),$(call prefix_linux,$(strip $1)))

# Targets used when cross building.
.PHONY: native register
native:
ifneq ($(BUILDARCH),$(ARCH))
	@echo "Target $(MAKECMDGOALS)" is not supported when cross building! && false
endif

# Enable binfmt adding support for miscellaneous binary formats.
# This is only needed when running non-native binaries.
register:
ifneq ($(BUILDARCH),$(ARCH))
	docker run --rm --privileged multiarch/qemu-user-static:register || true
endif

# list of arches *not* to build when doing *-all
#    until s390x works correctly
EXCLUDEARCH ?= s390x
VALIDARCHES = $(filter-out $(EXCLUDEARCH),$(ARCHES))

###############################################################################
BUILD_IMAGE?=calico/felix
PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/felix
RELEASE_IMAGES?=
PACKAGE_NAME?=github.com/projectcalico/felix

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
PUSH_IMAGES+=$(RELEASE_IMAGES)
endif

# remove from the list to push to manifest any registries that do not support multi-arch
EXCLUDE_MANIFEST_REGISTRIES ?= quay.io/
PUSH_MANIFEST_IMAGES=$(PUSH_IMAGES:$(EXCLUDE_MANIFEST_REGISTRIES)%=)
PUSH_NONMANIFEST_IMAGES=$(filter-out $(PUSH_MANIFEST_IMAGES),$(PUSH_IMAGES))

# location of docker credentials to push manifests
DOCKER_CONFIG ?= $(HOME)/.docker/config.json

GO_BUILD_VER?=v0.25
CGO_BUILD_VER?=v0.25-deb-cgo-4
# For building, we use the go-build image for the *host* architecture, even if the target is different
# the one for the host should contain all the necessary cross-compilation tools
# we do not need to use the arch since go-build:v0.15 now is multi-arch manifest
CALICO_BUILD=calico/go-build:$(GO_BUILD_VER)
CALICO_BUILD_CGO=calico/go-build:$(CGO_BUILD_VER)
ETCD_VERSION?=v3.3.7
K8S_VERSION?=v1.14.1
PROTOC_VER?=v0.1
PROTOC_CONTAINER ?=calico/protoc:$(PROTOC_VER)-$(BUILDARCH)

FV_ETCDIMAGE?=quay.io/coreos/etcd:$(ETCD_VERSION)-$(BUILDARCH)
FV_K8SIMAGE?=gcr.io/google_containers/hyperkube-$(BUILDARCH):$(K8S_VERSION)
FV_TYPHAIMAGE?=calico/typha:master-$(BUILDARCH)
FV_FELIXIMAGE?=calico/felix:latest-$(BUILDARCH)

# If building on amd64 omit the arch in the container name.  Fixme!
ifeq ($(BUILDARCH),amd64)
	FV_ETCDIMAGE=quay.io/coreos/etcd:$(ETCD_VERSION)
	FV_K8SIMAGE=gcr.io/google_containers/hyperkube:$(K8S_VERSION)
	FV_TYPHAIMAGE=calico/typha:master
endif

# Total number of ginkgo batches to run.  The CI system sets this according to the number
# of jobs that it divides the FVs into.
FV_NUM_BATCHES?=3
# Space-delimited list of FV batches to run in parallel.  Defaults to running all batches
# in parallel on this host.  The CI system runs a subset of batches in each parallel job.
FV_BATCHES_TO_RUN?=$(shell seq $(FV_NUM_BATCHES))
FV_SLOW_SPEC_THRESH=90

# Figure out version information.  To support builds from release tarballs, we default to
# <unknown> if this isn't a git checkout.
GIT_COMMIT:=$(shell git rev-parse HEAD || echo '<unknown>')
BUILD_ID:=$(shell git rev-parse HEAD || uuidgen | sed 's/-//g')
GIT_DESCRIPTION:=$(shell git describe --tags --dirty --always || echo '<unknown>')
ifeq ($(LOCAL_BUILD),true)
	GIT_DESCRIPTION = $(shell git describe --tags --dirty --always || echo '<unknown>')-dev-build
endif

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

# Linker flags for building Felix.
#
# We use -X to insert the version information into the placeholder variables
# in the buildinfo package.
#
# We use -B to insert a build ID note into the executable, without which, the
# RPM build tools complain.
LDFLAGS:=-ldflags "\
	-X $(PACKAGE_NAME)/buildinfo.GitVersion=$(GIT_DESCRIPTION) \
	-X $(PACKAGE_NAME)/buildinfo.BuildDate=$(DATE) \
	-X $(PACKAGE_NAME)/buildinfo.GitRevision=$(GIT_COMMIT) \
	-B 0x$(BUILD_ID)"

# List of Go files that are generated by the build process.  Builds should
# depend on these, clean removes them.
GENERATED_FILES:=proto/felixbackend.pb.go bpf/asm/opcode_string.go

# All Felix go files.
SRC_FILES:=$(shell find . $(foreach dir,$(NON_FELIX_DIRS),-path ./$(dir) -prune -o) -type f -name '*.go' -print) $(GENERATED_FILES)

# If local build is set, then always build the binary since we might not
# detect when another local repository has been modified.
ifeq ($(LOCAL_BUILD),true)
.PHONY: $(SRC_FILES)
endif

# Figure out the users UID/GID.  These are needed to run docker containers
# as the current user and ensure that files built inside containers are
# owned by the current user.
LOCAL_USER_ID:=$(shell id -u)
LOCAL_GROUP_ID:=$(shell id -g)

# Allow the ssh auth sock to be mapped into the build container.
ifdef SSH_AUTH_SOCK
	EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif

# Volume-mount gopath into the build container to cache go module's packages. If the environment is using multiple
# comma-separated directories for gopath, use the first one, as that is the default one used by go modules.
ifneq ($(GOPATH),)
	# If the environment is using multiple comma-separated directories for gopath, use the first one, as that
	# is the default one used by go modules.
	GOMOD_CACHE = $(shell echo $(GOPATH) | cut -d':' -f1)/pkg/mod
else
	# If gopath is empty, default to $(HOME)/go.
	GOMOD_CACHE = $(HOME)/go/pkg/mod
endif

EXTRA_DOCKER_ARGS	+= -e GO111MODULE=on -v $(GOMOD_CACHE):/go/pkg/mod:rw

# Build mounts for running in "local build" mode. This allows an easy build using local development code,
# assuming that there is a local checkout of libcalico, typha and pod2daemon in the same directory as this repo.
ifdef LOCAL_BUILD
PHONY: set-up-local-build
LOCAL_BUILD_DEP:=set-up-local-build
EXTRA_DOCKER_ARGS+=-v $(CURDIR)/../libcalico-go:/go/src/github.com/projectcalico/libcalico-go:rw
EXTRA_DOCKER_ARGS+=-v $(CURDIR)/../typha:/go/src/github.com/projectcalico/typha:rw
EXTRA_DOCKER_ARGS+=-v $(CURDIR)/../pod2daemon:/go/src/github.com/projectcalico/pod2daemon:rw
set-up-local-build:
	$(DOCKER_RUN) $(CALICO_BUILD) go mod edit -replace=github.com/projectcalico/libcalico-go=../libcalico-go
	$(DOCKER_RUN) $(CALICO_BUILD) go mod edit -replace=github.com/projectcalico/typha=../typha
	$(DOCKER_RUN) $(CALICO_BUILD) go mod edit -replace=github.com/projectcalico/pod2daemon=../pod2daemon
endif

DOCKER_RUN := mkdir -p .go-pkg-cache $(GOMOD_CACHE) && \
	docker run --rm \
		--net=host \
		--init \
		$(EXTRA_DOCKER_ARGS) \
		-e LOCAL_USER_ID=$(LOCAL_USER_ID) \
		-e GOCACHE=/go-cache \
		-e GOARCH=$(ARCH) \
		-e GOPATH=/go \
		-v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
		-v $(CURDIR)/.go-pkg-cache:/go-cache:rw \
		-w /go/src/$(PACKAGE_NAME)

.PHONY: clean
clean:
	rm -rf bin \
	       docker-image/bin \
	       dist \
	       build \
	       fv/fv.test \
	       $(GENERATED_FILES) \
	       go/docs/calc.pdf \
	       release-notes-* \
	       fv/infrastructure/crds.yaml
	find . -name "junit.xml" -type f -delete
	find . -name "*.coverprofile" -type f -delete
	find . -name "coverage.xml" -type f -delete
	find . -name ".coverage" -type f -delete
	find . -name "*.pyc" -type f -delete

###############################################################################
# Updating pins
###############################################################################
PIN_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)

define get_remote_version
	$(shell git ls-remote http://$(1) $(2) 2>/dev/null | cut -f 1)
endef

# update_pin updates the given package's version to the latest available in the specified repo and branch.
# $(1) should be the name of the package, $(2) and $(3) the repository and branch from which to update it.
define update_pin
	$(eval new_ver := $(call get_remote_version,$(2),$(3)))

	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '\
		if [[ ! -z "$(new_ver)" ]]; then \
			go get $(1)@$(new_ver); \
			go mod download; \
		fi'
endef

TYPHA_BRANCH?=$(PIN_BRANCH)
TYPHA_REPO?=github.com/projectcalico/typha
LIBCALICO_BRANCH?=$(PIN_BRANCH)
LIBCALICO_REPO?=github.com/projectcalico/libcalico-go

update-typha-pin:
	$(call update_pin,github.com/projectcalico/typha,$(TYPHA_REPO),$(TYPHA_BRANCH))

update-libcalico-pin:
	$(call update_pin,github.com/projectcalico/libcalico-go,$(LIBCALICO_REPO),$(LIBCALICO_BRANCH))

git-status:
	git status --porcelain

git-config:
ifdef CONFIRM
	git config --global user.name "Semaphore Automatic Update"
	git config --global user.email "marvin@projectcalico.io"
endif

git-commit:
	git diff --quiet HEAD || git commit -m "Semaphore Automatic Update" go.mod go.sum

git-push:
	git push

update-pins: update-libcalico-pin update-typha-pin

commit-pin-updates: update-pins git-status ci git-config git-commit git-push

###############################################################################
# Building the binary
###############################################################################
build: bin/calico-felix
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

bin/calico-felix: bin/calico-felix-$(ARCH)
	ln -f bin/calico-felix-$(ARCH) bin/calico-felix

bin/calico-felix-$(ARCH): $(SRC_FILES) $(LOCAL_BUILD_DEP)
	@echo Building felix for $(ARCH) on $(BUILDARCH)
	mkdir -p bin
	if [ "$(SEMAPHORE)" != "true" -o ! -e $@ ] ; then \
	  $(DOCKER_RUN) $(CALICO_BUILD_CGO) \
	     sh -c 'go build -v -i -o $@ -v $(BUILD_FLAGS) $(LDFLAGS) "$(PACKAGE_NAME)/cmd/calico-felix"'; \
	fi

# Generate the protobuf bindings for go. The proto/felixbackend.pb.go file is included in SRC_FILES
protobuf proto/felixbackend.pb.go: proto/felixbackend.proto
	docker run --rm --user $(LOCAL_USER_ID):$(LOCAL_GROUP_ID) \
		  -v $(CURDIR):/code -v $(CURDIR)/proto:/src:rw \
		      $(PROTOC_CONTAINER) \
		      --gogofaster_out=plugins=grpc:. \
		      felixbackend.proto

BPF_INC_FILES := $(shell find bpf -name '*.h')
BPF_C_FILES := $(shell find bpf -name '*.c')
BPF_XDP_INC_FILES :=

.PHONY: xdp

ifndef LOCAL
xdp bpf/bin/xdp_filter.o:
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
	              /bin/sh -c "make -C bpf/xdp all"
	mv bpf/xdp/filter.o bpf/bin/xdp_filter.o

xdp-clean:
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
	              /bin/sh -c "make -C bpf/xdp clean"

bpf-cgroup bpf/cgroup/connect_balance.o:
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
	              /bin/sh -c "make -C bpf/cgroup all"

bpf-cgroup-clean:
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
	              /bin/sh -c "make -C bpf/cgroup clean"
else
xdp bpf/bin/xdp_filter.o:
	$(MAKE) -C bpf/xdp
	cp bpf/xdp/filter.o bpf/bin/xdp_filter.o

xdp-clean:
	$(MAKE) -C bpf/xdp clean
endif

BPF_SOCKMAP_INC_FILES := bpf/sockmap/sockops.h

bpf/bin/sockops.o: bpf/sockmap/sockops.c $(BPF_INC_FILES) $(BPF_SOCKMAP_INC_FILES)
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
		      /bin/sh -c \
		      "clang \
			      -D__KERNEL__ \
			      -D__ASM_SYSREG_H \
			      -Wno-unused-value \
			      -Wno-pointer-sign \
			      -Wno-compare-distinct-pointer-types \
			      -Wunused \
			      -Wall \
			      -Werror \
			      -fno-stack-protector \
			      -O2 \
			      -emit-llvm \
			      -c /go/src/$(PACKAGE_NAME)/bpf/sockmap/sockops.c \
			      -o /go/src/$(PACKAGE_NAME)/bpf/sockmap/sockops.ll && \
		       llc \
			       -march=bpf \
			       -filetype=obj \
			       -o /go/src/$(PACKAGE_NAME)/bpf/bin/sockops.o \
			       /go/src/$(PACKAGE_NAME)/bpf/sockmap/sockops.ll && \
		       rm -f /go/src/$(PACKAGE_NAME)/bpf/sockmap/sockops.ll"

bpf/bin/redir.o: bpf/sockmap/redir.c $(BPF_INC_FILES) $(BPF_SOCKMAP_INC_FILES)
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
		      /bin/sh -c \
		      "clang \
			      -D__KERNEL__ \
			      -D__ASM_SYSREG_H \
			      -Wno-unused-value \
			      -Wno-pointer-sign \
			      -Wno-compare-distinct-pointer-types \
			      -Wunused \
			      -Wall \
			      -Werror \
			      -fno-stack-protector \
			      -O2 \
			      -emit-llvm \
			      -c /go/src/$(PACKAGE_NAME)/bpf/sockmap/redir.c \
			      -o /go/src/$(PACKAGE_NAME)/bpf/sockmap/redir.ll && \
		       llc \
			       -march=bpf \
			       -filetype=obj \
			       -o /go/src/$(PACKAGE_NAME)/bpf/bin/redir.o \
			       /go/src/$(PACKAGE_NAME)/bpf/sockmap/redir.ll && \
		       rm -f /go/src/$(PACKAGE_NAME)/bpf/sockmap/redir.ll"

bpf/asm/opcode_string.go: bpf/asm/asm.go
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) go generate ./bpf/asm/

###############################################################################
# Building the image
###############################################################################
# Build the calico/felix docker image, which contains only Felix.
.PHONY: $(BUILD_IMAGE) $(BUILD_IMAGE)-$(ARCH)

# by default, build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

bin/compile-bpf: $(GENERATED_FILES) go.mod $(shell find cmd/compile-bpf bpf/nat bpf/tc config logutils proto -type f -name '*.go' -print | grep -v '_test\.go' )
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) go build -o $@ ./cmd/compile-bpf

bin/bpf-progs.inc: bin/compile-bpf
	bin/compile-bpf gen-makefile-inc > $@.tmp
	mv $@.tmp $@

# bpf-progs.inc sets up the BPF_PROGS variable.  The target above will cause it to be auto-updated after switching
# branch.
include bin/bpf-progs.inc

# BPF programs built by the makefile.
MAKEFILE_BPF_PROGS:=\
	bpf/bin/xdp_filter.o \
	bpf/bin/redir.o \
	bpf/bin/sockops.o

ALL_BPF_PROGS:=$(BPF_PROGS) $(MAKEFILE_BPF_PROGS)

$(BPF_PROGS): $(BPF_C_FILES) $(BPF_INC_FILES) bin/compile-bpf
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) bin/compile-bpf

build-bpf: $(ALL_BPF_PROGS)

image: $(BUILD_IMAGE)
$(BUILD_IMAGE): $(BUILD_IMAGE)-$(ARCH)
$(BUILD_IMAGE)-$(ARCH): bin/calico-felix-$(ARCH) \
                        bin/calico-bpf \
                        $(ALL_BPF_PROGS) \
                        docker-image/calico-felix-wrapper \
                        docker-image/felix.cfg \
                        docker-image/Dockerfile* \
                        register
	# Reconstruct the bin and bpf directories because we don't want to accidentally add
	# leftover files (say from a build on another branch) into the docker image.
	rm -rf docker-image/bin
	mkdir -p docker-image/bin
	cp bin/calico-felix-$(ARCH) docker-image/bin/
	cp bin/calico-bpf docker-image/bin/
	rm -rf docker-image/bpf
	mkdir -p docker-image/bpf/bin
	# Copy only the files we're explicitly expecting (in case we have left overs after switching branch).
	cp $(ALL_BPF_PROGS) docker-image/bpf/bin
	if [ "$(SEMAPHORE)" != "true" -o "$$(docker images -q $(BUILD_IMAGE):latest-$(ARCH) 2> /dev/null)" = "" ] ; then \
 	  docker build --pull -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --file ./docker-image/Dockerfile.$(ARCH) docker-image; \
	fi
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif

imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))

sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

## push all arches
push-all: imagetag $(addprefix sub-push-,$(VALIDARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

## push multi-arch manifest where supported
push-manifests: imagetag  $(addprefix sub-manifest-,$(call escapefs,$(PUSH_MANIFEST_IMAGES)))
sub-manifest-%:
	# Docker login to hub.docker.com required before running this target as we are using $(DOCKER_CONFIG) holds the docker login credentials
	# path to credentials based on manifest-tool's requirements here https://github.com/estesp/manifest-tool#sample-usage
	docker run -t --entrypoint /bin/sh -v $(DOCKER_CONFIG):/root/.docker/config.json $(CALICO_BUILD) -c "/usr/bin/manifest-tool push from-args --platforms $(call join_platforms,$(VALIDARCHES)) --template $(call unescapefs,$*:$(IMAGETAG))-ARCH --target $(call unescapefs,$*:$(IMAGETAG))"

## push default amd64 arch where multi-arch manifest is not supported
push-non-manifests: imagetag $(addprefix sub-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))
sub-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker push $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of one arch for all supported registries
tag-images: imagetag $(addprefix sub-single-tag-images-arch-,$(call escapefs,$(PUSH_IMAGES))) $(addprefix sub-single-tag-images-non-manifest-,$(call escapefs,$(PUSH_NONMANIFEST_IMAGES)))

sub-single-tag-images-arch-%:
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

# because some still do not support multi-arch manifest
sub-single-tag-images-non-manifest-%:
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(call unescapefs,$*:$(IMAGETAG))
else
	$(NOECHO) $(NOOP)
endif

## tag images of all archs
tag-images-all: imagetag $(addprefix sub-tag-images-,$(VALIDARCHES))
sub-tag-images-%:
	$(MAKE) tag-images ARCH=$* IMAGETAG=$(IMAGETAG)

###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks
static-checks:
	$(MAKE) check-typha-pins golangci-lint

LINT_ARGS := --deadline 5m --max-issues-per-linter 0 --max-same-issues 0 --skip-dirs=docker-image
ifneq ($(CI),)
	# govet uses too much memory for CI
	LINT_ARGS += --disable govet
endif

.PHONY: golangci-lint
golangci-lint: $(GENERATED_FILES)
	$(DOCKER_RUN) -e GOGC=10 $(CALICO_BUILD_CGO) golangci-lint run $(LINT_ARGS)

# Run go fmt on all our go files.
.PHONY: go-fmt goimports fix
fix go-fmt goimports:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'find . -iname "*.go" ! -wholename "./vendor/*" | xargs goimports -w -local github.com/projectcalico/'

LIBCALICO_FELIX?=$(shell $(DOCKER_RUN) $(CALICO_BUILD) go list -m -f "{{.Version}}" github.com/projectcalico/libcalico-go)
TYPHA_GOMOD?=$(shell $(DOCKER_RUN) $(CALICO_BUILD) go list -m -f "{{.GoMod}}" github.com/projectcalico/typha)
ifneq ($(TYPHA_GOMOD),)
	LIBCALICO_TYPHA?=$(shell $(DOCKER_RUN) $(CALICO_BUILD) grep libcalico-go $(TYPHA_GOMOD) | cut -d' ' -f2)
endif

.PHONY: check-typha-pins
check-typha-pins:
	@echo "Checking Typha's libcalico-go pin matches ours (so that any datamodel"
	@echo "changes are reflected in the Typha-Felix API)."
	@echo
	@echo "Felix's libcalico-go pin: $(LIBCALICO_FELIX)"
	@echo "Typha's libcalico-go pin: $(LIBCALICO_TYPHA)"
	if [ "$(LIBCALICO_FELIX)" != "$(LIBCALICO_TYPHA)" ]; then \
	     echo "Typha and Felix libcalico-go pins differ."; \
	     false; \
	fi

.PHONY: pre-commit
pre-commit:
	$(DOCKER_RUN) $(CALICO_BUILD) git-hooks/pre-commit-in-container

.PHONY: install-git-hooks
install-git-hooks:
	./install-git-hooks

foss-checks:
	$(DOCKER_RUN) -e FOSSA_API_KEY=$(FOSSA_API_KEY) $(CALICO_BUILD) /usr/local/bin/fossa

###############################################################################
# Unit Tests
###############################################################################

UT_PACKAGES_TO_SKIP?=fv,k8sfv,bpf/ut

.PHONY: ut
ut combined.coverprofile: $(SRC_FILES) $(ALL_BPF_PROGS)
	@echo Running Go UTs.
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) ./utils/run-coverage -skipPackage $(UT_PACKAGES_TO_SKIP) $(GINKGO_ARGS)

###############################################################################
# FV Tests
###############################################################################
fv/fv.test: $(SRC_FILES)
	# We pre-build the FV test binaries so that we can run them
	# outside a container and allow them to interact with docker.
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) go test $(BUILD_FLAGS) ./$(shell dirname $@) -c --tags fvtests -o $@

REMOTE_DEPS=fv/infrastructure/crds.yaml

fv/infrastructure/crds.yaml: go.mod go.sum
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c ' \
	go list all; \
	cp `go list -m -f "{{.Dir}}" github.com/projectcalico/libcalico-go`/test/crds.yaml fv/infrastructure/crds.yaml; \
	chmod +w fv/infrastructure/crds.yaml'

.PHONY: fv
# runs all of the fv tests
# to run it in parallel, decide how many parallel engines you will run, and in each one call:
#	 $(MAKE) fv FV_BATCHES_TO_RUN="<num>" FV_NUM_BATCHES=<num>
# where
#	 FV_NUM_BATCHES = total parallel batches
#	 FV_BATCHES_TO_RUN = which number this is
# e.g. to run it in 10 parallel runs:
#	 $(MAKE) fv FV_BATCHES_TO_RUN="1" FV_NUM_BATCHES=10     # the first 1/10
#	 $(MAKE) fv FV_BATCHES_TO_RUN="2" FV_NUM_BATCHES=10     # the second 1/10
#	 $(MAKE) fv FV_BATCHES_TO_RUN="3" FV_NUM_BATCHES=10     # the third 1/10
#	 ...
#	 $(MAKE) fv FV_BATCHES_TO_RUN="10" FV_NUM_BATCHES=10    # the tenth 1/10
#	 etc.
fv fv/latency.log: $(REMOTE_DEPS) $(BUILD_IMAGE) bin/iptables-locker bin/test-workload bin/test-connection bin/calico-bpf fv/fv.test
	cd fv && \
	  FV_FELIXIMAGE=$(FV_FELIXIMAGE) \
	  FV_ETCDIMAGE=$(FV_ETCDIMAGE) \
	  FV_TYPHAIMAGE=$(FV_TYPHAIMAGE) \
	  FV_K8SIMAGE=$(FV_K8SIMAGE) \
	  FV_NUM_BATCHES=$(FV_NUM_BATCHES) \
	  FV_BATCHES_TO_RUN="$(FV_BATCHES_TO_RUN)" \
	  PRIVATE_KEY=`pwd`/private.key \
	  GINKGO_ARGS='$(GINKGO_ARGS)' \
	  GINKGO_FOCUS="$(GINKGO_FOCUS)" \
	  FELIX_FV_ENABLE_BPF="$(FELIX_FV_ENABLE_BPF)" \
	  ./run-batches
	@if [ -e fv/latency.log ]; then \
	   echo; \
	   echo "Latency results:"; \
	   echo; \
	   cat fv/latency.log; \
	fi

fv-bpf:
	$(MAKE) fv FELIX_FV_ENABLE_BPF=true

###############################################################################
# K8SFV Tests
###############################################################################
# Targets for Felix testing with the k8s backend and a k8s API server,
# with k8s model resources being injected by a separate test client.
GET_CONTAINER_IP := docker inspect --format='{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}'
GRAFANA_VERSION=4.1.2
PROMETHEUS_DATA_DIR := $$HOME/prometheus-data
K8SFV_PROMETHEUS_DATA_DIR := $(PROMETHEUS_DATA_DIR)/k8sfv
$(K8SFV_PROMETHEUS_DATA_DIR):
	mkdir -p $@

# Directories that aren't part of the main Felix program,
# e.g. standalone test programs.
K8SFV_DIR:=k8sfv
NON_FELIX_DIRS:=$(K8SFV_DIR)
# Files for the Felix+k8s backend test program.
K8SFV_GO_FILES:=$(shell find ./$(K8SFV_DIR) -name prometheus -prune -o -type f -name '*.go' -print)

.PHONY: k8sfv-test k8sfv-test-existing-felix
# Run k8sfv test with Felix built from current code.
# control whether or not we use typha with USE_TYPHA=true or USE_TYPHA=false
# e.g.
#       $(MAKE) k8sfv-test JUST_A_MINUTE=true USE_TYPHA=true
#       $(MAKE) k8sfv-test JUST_A_MINUTE=true USE_TYPHA=false
k8sfv-test: $(BUILD_IMAGE) k8sfv-test-existing-felix
# Run k8sfv test with whatever is the existing 'calico/felix:latest'
# container image.  To use some existing Felix version other than
# 'latest', do 'FELIX_VERSION=<...> make k8sfv-test-existing-felix'.
k8sfv-test-existing-felix: $(REMOTE_DEPS) bin/k8sfv.test
	FV_ETCDIMAGE=$(FV_ETCDIMAGE) \
	FV_TYPHAIMAGE=$(FV_TYPHAIMAGE) \
	FV_FELIXIMAGE=$(FV_FELIXIMAGE) \
	FV_K8SIMAGE=$(FV_K8SIMAGE) \
	PRIVATE_KEY=`pwd`/fv/private.key \
	k8sfv/run-test

bin/k8sfv.test: $(K8SFV_GO_FILES)
	@echo Building $@...
	$(DOCKER_RUN) $(CALICO_BUILD) \
	    sh -c 'go test -c $(BUILD_FLAGS) -o $@ ./k8sfv'

.PHONY: run-prometheus run-grafana stop-prometheus stop-grafana
run-prometheus: stop-prometheus $(K8SFV_PROMETHEUS_DATA_DIR)
	FELIX_IP=`$(GET_CONTAINER_IP) k8sfv-felix` && \
	sed "s/__FELIX_IP__/$${FELIX_IP}/" < $(K8SFV_DIR)/prometheus/prometheus.yml.in > $(K8SFV_DIR)/prometheus/prometheus.yml
	docker run --detach --name k8sfv-prometheus \
	-v $(CURDIR)/$(K8SFV_DIR)/prometheus/prometheus.yml:/etc/prometheus.yml \
	-v $(K8SFV_PROMETHEUS_DATA_DIR):/prometheus \
	prom/prometheus \
	-config.file=/etc/prometheus.yml \
	-storage.local.path=/prometheus

stop-prometheus:
	@-docker rm -f k8sfv-prometheus
	sleep 2

run-grafana: stop-grafana run-prometheus
	docker run --detach --name k8sfv-grafana -p 3000:3000 \
	-v $(CURDIR)/$(K8SFV_DIR)/grafana:/etc/grafana \
	-v $(CURDIR)/$(K8SFV_DIR)/grafana-dashboards:/etc/grafana-dashboards \
	grafana/grafana:$(GRAFANA_VERSION) --config /etc/grafana/grafana.ini
	# Wait for it to get going.
	sleep 5
	# Configure prometheus data source.
	PROMETHEUS_IP=`$(GET_CONTAINER_IP) k8sfv-prometheus` && \
	sed "s/__PROMETHEUS_IP__/$${PROMETHEUS_IP}/" < $(K8SFV_DIR)/grafana-datasources/my-prom.json.in | \
	curl 'http://admin:admin@127.0.0.1:3000/api/datasources' -X POST \
	    -H 'Content-Type: application/json;charset=UTF-8' --data-binary @-

stop-grafana:
	@-docker rm -f k8sfv-grafana
	sleep 2

bin/calico-bpf: $(SRC_FILES) $(LOCAL_BUILD_DEP)
	@echo Building calico-bpf...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) \
	    sh -c 'go build -v -i -o $@ -v $(BUILD_FLAGS) $(LDFLAGS) "$(PACKAGE_NAME)/cmd/calico-bpf"'

bin/iptables-locker: $(LOCAL_BUILD_DEP) go.mod $(shell find iptables -type f -name '*.go' -print)
	@echo Building iptables-locker...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) \
	    sh -c 'go build -v -i -o $@ -v $(BUILD_FLAGS) $(LDFLAGS) "$(PACKAGE_NAME)/fv/iptables-locker"'

bin/test-workload: $(LOCAL_BUILD_DEP) go.mod fv/cgroup/cgroup.go fv/utils/utils.go fv/connectivity/*.go fv/test-workload/*.go
	@echo Building test-workload...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) \
	    sh -c 'go build -v -i -o $@ -v $(BUILD_FLAGS) $(LDFLAGS) "$(PACKAGE_NAME)/fv/test-workload"'

bin/test-connection: $(LOCAL_BUILD_DEP) go.mod fv/cgroup/cgroup.go fv/utils/utils.go fv/connectivity/*.go fv/test-connection/*.go
	@echo Building test-connection...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) \
	    sh -c 'go build -v -i -o $@ -v $(BUILD_FLAGS) $(LDFLAGS) "$(PACKAGE_NAME)/fv/test-connection"'

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci cd mod-download
mod-download:
	-$(DOCKER_RUN) $(CALICO_BUILD) go mod download

ci: mod-download image-all ut
ifeq (,$(filter fv, $(EXCEPT)))
	@$(MAKE) fv
endif
ifeq (,$(filter k8sfv-test, $(EXCEPT)))
	@$(MAKE) k8sfv-test JUST_A_MINUTE=true USE_TYPHA=true
	@$(MAKE) k8sfv-test JUST_A_MINUTE=true USE_TYPHA=false
endif

## Deploy images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(BRANCH_NAME) EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long) EXCLUDEARCH="$(EXCLUDEARCH)"

###############################################################################
# Release
###############################################################################
PREVIOUS_RELEASE=$(shell git describe --tags --abbrev=0)
GIT_VERSION?=$(shell git describe --tags --dirty)

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

	$(MAKE) image-all
	$(MAKE) tag-images-all IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-images-all IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	for img in $(BUILD_IMAGE):$(VERSION)-$(ARCH) quay.io/$(BUILD_IMAGE):$(VERSION)-$(ARCH); do \
	  if docker run $$img calico-felix --version | grep -q '$(VERSION)$$'; \
	  then \
	    echo "Check successful. ($$img)"; \
	  else \
	    echo "Incorrect version in docker image $$img!"; \
	    result=false; \
	  fi \
	done; \

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
	# Disabling for now since no-one is consuming the images.
	# $(MAKE) push-all IMAGETAG=$(VERSION)

	# Push binaries to GitHub release.
	# Requires ghr: https://github.com/tcnksm/ghr
	# Requires GITHUB_TOKEN environment variable set.
	ghr -u projectcalico -r felix \
		-b "Release notes can be found at https://docs.projectcalico.org" \
		-n $(VERSION) \
		$(VERSION) ./bin/

	@echo "Confirm that the release was published at the following URL."
	@echo ""
	@echo "  https://$(PACKAGE_NAME)/releases/tag/$(VERSION)"
	@echo ""
	@echo "Build and publish the debs and rpms for this release."
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
	for img in $(BUILD_IMAGE):latest-$(ARCH) quay.io/$(BUILD_IMAGE):latest-$(ARCH); do \
	  if docker run $$img calico-felix --version | grep -q '$(VERSION)$$'; \
	  then \
	    echo "Check successful. ($$img)"; \
	  else \
	    echo "Incorrect version in docker image $$img!"; \
	    result=false; \
	  fi \
	done; \

	# Disabling for now since no-one is consuming the images.
	# $(MAKE) push-all IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set for a release)
endif
ifeq (, $(shell which ghr))
	$(error Unable to find `ghr` in PATH, run this: go get -u github.com/tcnksm/ghr)
endif

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: ut-no-cover
ut-no-cover: $(SRC_FILES)
	@echo Running Go UTs without coverage.
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) ginkgo -r -skipPackage $(UT_PACKAGES_TO_SKIP) $(GINKGO_ARGS)

.PHONY: ut-watch
ut-watch: $(SRC_FILES)
	@echo Watching go UTs for changes...
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) ginkgo watch -r -skipPackage $(UT_PACKAGES_TO_SKIP) $(GINKGO_ARGS)

.PHONY: bin/bpf.test
bin/bpf.test: $(GENERATED_FILES) $(shell find bpf/ -name '*.go')
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) go test $(BUILD_FLAGS) ./bpf/ -c -o $@

.PHONY: bin/bpf.test
bin/bpf_ut.test: $(GENERATED_FILES) $(shell find bpf/ -name '*.go')
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) go test $(BUILD_FLAGS) ./bpf/ut -c -o $@

# Build debug version of bpf.test for use with the delve debugger.
.PHONY: bin/bpf_debug.test
bin/bpf_debug.test: $(GENERATED_FILES)
	$(DOCKER_RUN) $(CALICO_BUILD_CGO) go test $(BUILD_FLAGS) ./bpf/ut -c -gcflags="-N -l" -o $@

.PHONY: bpf-ut
bpf-ut: bin/bpf_ut.test bin/bpf.test $(ALL_BPF_PROGS)
	$(DOCKER_RUN) \
		--privileged \
		-e RUN_AS_ROOT=true \
		$(CALICO_BUILD_CGO) sh -c ' \
		mount bpffs /sys/fs/bpf -t bpf && \
		cd /go/src/$(PACKAGE_NAME)/bpf/ && \
		BPF_FORCE_REAL_LIB=true ../bin/bpf.test -test.v -test.run "$(FOCUS)"'
	$(DOCKER_RUN) \
		--privileged \
		-e RUN_AS_ROOT=true \
		-v `pwd`:/code \
		$(CALICO_BUILD_CGO) sh -c ' \
		mount bpffs /sys/fs/bpf -t bpf && \
		cd /go/src/$(PACKAGE_NAME)/bpf/ut && \
		../../bin/bpf_ut.test -test.v -test.run "$(FOCUS)"'

# Launch a browser with Go coverage stats for the whole project.
.PHONY: cover-browser
cover-browser: combined.coverprofile
	go tool cover -html="combined.coverprofile"

.PHONY: cover-report
cover-report: combined.coverprofile
	# Print the coverage.  We use sed to remove the verbose prefix and trim down
	# the whitespace.
	@echo
	@echo ======== All coverage =========
	@echo
	@$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'go tool cover -func combined.coverprofile | \
				   sed 's=$(PACKAGE_NAME)/==' | \
				   column -t'
	@echo
	@echo ======== Missing coverage only =========
	@echo
	@$(DOCKER_RUN) $(CALICO_BUILD) sh -c "go tool cover -func combined.coverprofile | \
				   sed 's=$(PACKAGE_NAME)/==' | \
				   column -t | \
				   grep -v '100\.0%'"

bin/calico-felix.transfer-url: bin/calico-felix
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'curl --upload-file bin/calico-felix https://transfer.sh/calico-felix > $@'

.PHONY: patch-script
patch-script: bin/calico-felix.transfer-url
	$(DOCKER_RUN) $(CALICO_BUILD) bash -c 'utils/make-patch-script.sh $$(cat bin/calico-felix.transfer-url)'

# Generate a diagram of Felix's internal calculation graph.
docs/calc.pdf: docs/calc.dot
	cd docs/ && dot -Tpdf calc.dot -o calc.pdf

# Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/onsi/ginkgo/ginkgo

help:
	@echo "Felix Makefile"
	@echo
	@echo "Dependencies: docker 1.12+; go 1.7+"
	@echo
	@echo "Note: initial builds can be slow because they generate docker-based"
	@echo "build environments."
	@echo
	@echo "For any target, set ARCH=<target> to build for a given target."
	@echo "For example, to build for arm64:"
	@echo
	@echo "  make build ARCH=arm64"
	@echo
	@echo "To generate a docker image for arm64:"
	@echo
	@echo "  make image ARCH=arm64"
	@echo
	@echo "By default, builds for the architecture on which it is running. Cross-building is supported"
	@echo "only on amd64, i.e. building for other architectures when running on amd64."
	@echo "Supported target ARCH options:       $(ARCHES)"
	@echo
	@echo "Initial set-up:"
	@echo
	@echo "  make update-tools  Update/install the go build dependencies."
	@echo
	@echo "Builds:"
	@echo
	@echo "  make all		    Build all the binary packages."
	@echo "  make deb		    Build debs in ./dist."
	@echo "  make rpm		    Build rpms in ./dist."
	@echo "  make build		  Build binary."
	@echo "  make image		  Build docker image."
	@echo "  make build-all	      Build binary for all supported architectures."
	@echo "  make image-all	      Build docker images for all supported architectures."
	@echo "  make push IMAGETAG=tag      Deploy docker image with the tag IMAGETAG for the given ARCH, e.g. $(BUILD_IMAGE)<IMAGETAG>-<ARCH>."
	@echo "  make push-all IMAGETAG=tag  Deploy docker images with the tag IMAGETAG all supported architectures"
	@echo
	@echo "Tests:"
	@echo
	@echo "  make ut		Run UTs."
	@echo "  make go-cover-browser  Display go code coverage in browser."
	@echo
	@echo "Maintenance:"
	@echo
	@echo "  make go-fmt	Format our go code."
	@echo "  make clean	 Remove binary files."
	@echo "-----------------------------------------"
	@echo "ARCH (target):	  $(ARCH)"
	@echo "BUILDARCH (host):       $(BUILDARCH)"
	@echo "CALICO_BUILD:	   $(CALICO_BUILD)"
	@echo "PROTOC_CONTAINER:       $(PROTOC_CONTAINER)"
	@echo "FV_ETCDIMAGE:	   $(FV_ETCDIMAGE)"
	@echo "FV_K8SIMAGE:	    $(FV_K8SIMAGE)"
	@echo "FV_TYPHAIMAGE:	  $(FV_TYPHAIMAGE)"
	@echo "-----------------------------------------"
