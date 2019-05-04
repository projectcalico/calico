# Shortcut targets
default: build

## Build binary for current platform
all: build

## Run the tests for the current platform/architecture
test: ut

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

# Build mounts for running in "local build" mode. Mount in libcalico, but null out
# the vendor directory. This allows an easy build using local development code,
# assuming that there is a local checkout of libcalico in the same directory as this repo.
LOCAL_BUILD_MOUNTS ?=
ifeq ($(LOCAL_BUILD),true)
LOCAL_BUILD_MOUNTS = -v $(CURDIR)/../libcalico-go:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go:ro \
	-v $(CURDIR)/.empty:/go/src/$(PACKAGE_NAME)/vendor/github.com/projectcalico/libcalico-go/vendor:ro
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
.PHONY: register
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
BUILD_IMAGE=calico/typha
PACKAGE_NAME?=github.com/projectcalico/typha

PUSH_IMAGES?=$(BUILD_IMAGE) quay.io/calico/typha
RELEASE_IMAGES?=gcr.io/projectcalico-org/typha eu.gcr.io/projectcalico-org/typha asia.gcr.io/projectcalico-org/typha us.gcr.io/projectcalico-org/typha

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

GO_BUILD_VER?=v0.20
# For building, we use the go-build image for the *host* architecture, even if the target is different
# the one for the host should contain all the necessary cross-compilation tools
# we do not need to use the arch since go-build:v0.15 now is multi-arch manifest
CALICO_BUILD=calico/go-build:$(GO_BUILD_VER)

# Figure out version information.  To support builds from release tarballs, we default to
# <unknown> if this isn't a git checkout.
GIT_COMMIT:=$(shell git rev-parse HEAD || echo '<unknown>')
BUILD_ID:=$(shell git rev-parse HEAD || uuidgen | sed 's/-//g')
GIT_DESCRIPTION:=$(shell git describe --tags || echo '<unknown>')

# Calculate a timestamp for any build artefacts.
DATE:=$(shell date -u +'%FT%T%z')

# Linker flags for building Typha.
#
# We use -X to insert the version information into the placeholder variables
# in the buildinfo package.
#
# We use -B to insert a build ID note into the executable, without which, the
# RPM build tools complain.
LDFLAGS:=-ldflags "\
        -X $(PACKAGE_NAME)/pkg/buildinfo.GitVersion=$(GIT_DESCRIPTION) \
        -X $(PACKAGE_NAME)/pkg/buildinfo.BuildDate=$(DATE) \
        -X $(PACKAGE_NAME)/pkg/buildinfo.GitRevision=$(GIT_COMMIT) \
        -B 0x$(BUILD_ID)"

# List of Go files that are generated by the build process.  Builds should
# depend on these, clean removes them.
GENERATED_GO_FILES:=

# All Typha go files.
SRC_FILES:=$(shell find . $(foreach dir,$(NON_TYPHA_DIRS),-path ./$(dir) -prune -o) -type f -name '*.go' -print) $(GENERATED_GO_FILES)

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

# Allow libcalico-go and the ssh auth sock to be mapped into the build container.
ifdef LIBCALICOGO_PATH
  EXTRA_DOCKER_ARGS += -v $(LIBCALICOGO_PATH):/go/src/github.com/projectcalico/libcalico-go:ro
endif
ifdef SSH_AUTH_SOCK
  EXTRA_DOCKER_ARGS += -v $(SSH_AUTH_SOCK):/ssh-agent --env SSH_AUTH_SOCK=/ssh-agent
endif
DOCKER_RUN := mkdir -p .go-pkg-cache && \
                   docker run --rm \
                              --net=host \
                              $(EXTRA_DOCKER_ARGS) \
                              -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
                              -v $(HOME)/.glide:/home/user/.glide:rw \
                              -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
                              -v $(CURDIR)/.go-pkg-cache:/go/pkg:rw \
                              -w /go/src/$(PACKAGE_NAME) \
                              -e GOARCH=$(ARCH)

.PHONY: clean
clean:
	rm -rf bin \
	       docker-image/bin \
	       build \
	       $(GENERATED_GO_FILES) \
	       .glide \
	       vendor \
	       .go-pkg-cache \
	       check-licenses/dependency-licenses.txt \
	       report/*.xml \
	       release-notes-*
	find . -name "*.coverprofile" -type f -delete
	find . -name "coverage.xml" -type f -delete
	find . -name ".coverage" -type f -delete
	find . -name "*.pyc" -type f -delete

###############################################################################
# Building the binary
###############################################################################
build: bin/calico-typha
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

# Update the vendored dependencies with the latest upstream versions matching
# our glide.yaml.  If there area any changes, this updates glide.lock
# as a side effect.  Unless you're adding/updating a dependency, you probably
# want to use the vendor target to install the versions from glide.lock.
.PHONY: update-vendor
update-vendor:
	mkdir -p $$HOME/.glide
	$(DOCKER_RUN) $(CALICO_BUILD) glide up --strip-vendor
	touch vendor/.up-to-date

# vendor is a shortcut for force rebuilding the go vendor directory.
.PHONY: vendor
vendor: vendor/.up-to-date
vendor/.up-to-date: glide.lock
	mkdir -p $$HOME/.glide
	$(DOCKER_RUN) $(CALICO_BUILD) glide install --strip-vendor
	touch vendor/.up-to-date

# Default the libcalico repo and version but allow them to be overridden
LIBCALICO_BRANCH?=$(shell git rev-parse --abbrev-ref HEAD)
LIBCALICO_REPO?=github.com/projectcalico/libcalico-go
LIBCALICO_VERSION?=$(shell git ls-remote git@github.com:projectcalico/libcalico-go $(LIBCALICO_BRANCH) 2>/dev/null | cut -f 1)

## Update libcalico pin in glide.yaml
update-libcalico:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '\
        echo "Updating libcalico to $(LIBCALICO_VERSION) from $(LIBCALICO_REPO)"; \
        export OLD_VER=$$(grep --after 50 libcalico-go glide.yaml |grep --max-count=1 --only-matching --perl-regexp "version:\s*\K[^\s]+") ;\
        echo "Old version: $$OLD_VER";\
	if [ "$(LIBCALICO_VERSION)" != $$OLD_VER ]; then \
            sed -i "s/$$OLD_VER/$(LIBCALICO_VERSION)/" glide.yaml && \
	    if [ "$(LIBCALICO_REPO)" != "github.com/projectcalico/libcalico-go" ]; then \
              glide mirror set https://github.com/projectcalico/libcalico-go $(LIBCALICO_REPO) --vcs git; glide mirror list; \
            fi;\
          glide up --strip-vendor || glide up --strip-vendor; \
        fi'

bin/calico-typha: bin/calico-typha-$(ARCH)
	ln -f bin/calico-typha-$(ARCH) bin/calico-typha

bin/calico-typha-$(ARCH): $(SRC_FILES) vendor/.up-to-date
	@echo Building typha...
	mkdir -p bin
	$(DOCKER_RUN) $(LOCAL_BUILD_MOUNTS) $(CALICO_BUILD) \
	    sh -c 'go build -v -i -o $@ -v $(LDFLAGS) "$(PACKAGE_NAME)/cmd/calico-typha" && \
		( ldd $@ 2>&1 | grep -q -e "Not a valid dynamic program" \
		-e "not a dynamic executable" || \
		( echo "Error: bin/calico-typha was not statically linked"; false ) )'

bin/typha-client-$(ARCH): $(SRC_FILES) vendor/.up-to-date
	@echo Building typha client...
	mkdir -p bin
	$(DOCKER_RUN) $(LOCAL_BUILD_MOUNTS) $(CALICO_BUILD) \
	    sh -c 'go build -v -i -o $@ -v $(LDFLAGS) "$(PACKAGE_NAME)/cmd/typha-client" && \
		( ldd $@ 2>&1 | grep -q -e "Not a valid dynamic program" \
		-e "not a dynamic executable" || \
		( echo "Error: bin/typha-client was not statically linked"; false ) )'
###############################################################################
# Building the image
###############################################################################
# Build the calico/typha docker image, which contains only typha.
.PHONY: $(BUILD_IMAGE) $(BUILD_IMAGE)-$(ARCH)
image: $(BUILD_IMAGE)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# Build the calico/typha docker image, which contains only Typha.
.PHONY: image $(BUILD_IMAGE)
$(BUILD_IMAGE): bin/calico-typha-$(ARCH) register
	rm -rf docker-image/bin
	mkdir -p docker-image/bin
	cp bin/calico-typha-$(ARCH) docker-image/bin/
	docker build --pull -t $(BUILD_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --file ./docker-image/Dockerfile.$(ARCH) docker-image
ifeq ($(ARCH),amd64)
	docker tag $(BUILD_IMAGE):latest-$(ARCH) $(BUILD_IMAGE):latest
endif

# ensure we have a real imagetag
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

## push one arch
push: imagetag $(addprefix sub-single-push-,$(call escapefs,$(PUSH_IMAGES)))

sub-single-push-%:
	docker push $(call unescapefs,$*:$(IMAGETAG)-$(ARCH))

## push all archs
push-all: imagetag $(addprefix sub-push-,$(VALIDARCHES))
sub-push-%:
	$(MAKE) push ARCH=$* IMAGETAG=$(IMAGETAG)

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

## tag images of one arch
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
	$(MAKE) go-meta-linter check-licenses

bin/check-licenses: $(SRC_FILES)
	$(DOCKER_RUN) $(LOCAL_BUILD_MOUNTS) $(CALICO_BUILD) go build -v -i -o $@ "$(PACKAGE_NAME)/check-licenses"

.PHONY: check-licenses
check-licenses: check-licenses/dependency-licenses.txt bin/check-licenses
	@echo Checking dependency licenses
	$(DOCKER_RUN) $(CALICO_BUILD) bin/check-licenses

check-licenses/dependency-licenses.txt: vendor/.up-to-date
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'licenses ./cmd/calico-typha > check-licenses/dependency-licenses.tmp && \
	                          mv check-licenses/dependency-licenses.tmp check-licenses/dependency-licenses.txt'

foss-checks: vendor
	@echo Running $@...
	@docker run --rm -v $(CURDIR):/go/src/$(PACKAGE_NAME):rw \
	  -e LOCAL_USER_ID=$(LOCAL_USER_ID) \
	  -e FOSSA_API_KEY=$(FOSSA_API_KEY) \
	  -w /go/src/$(PACKAGE_NAME) \
	  $(CALICO_BUILD) /usr/local/bin/fossa

.PHONY: go-meta-linter
go-meta-linter: vendor/.up-to-date $(GENERATED_GO_FILES)
	# Run staticcheck stand-alone since gometalinter runs concurrent copies, which
	# uses a lot of RAM.
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'glide nv | xargs -n 3 staticcheck'
	$(DOCKER_RUN) $(CALICO_BUILD) gometalinter --enable-gc \
		--deadline=300s \
		--disable-all \
		--enable=goimports \
		--enable=errcheck \
		--vendor ./...

# Run go fmt on all our go files.
.PHONY: go-fmt goimports fix
go-fmt goimports fix:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'glide nv -x | \
	                          grep -v -e "^\\.$$" | \
	                          xargs goimports -w -local github.com/projectcalico/'

.PHONY: install-git-hooks
## Install Git hooks
install-git-hooks:
	./install-git-hooks

###############################################################################
# Unit Tests
###############################################################################
.PHONY: ut
ut combined.coverprofile: vendor/.up-to-date $(SRC_FILES)
	@echo Running Go UTs.
	$(DOCKER_RUN) $(LOCAL_BUILD_MOUNTS) $(CALICO_BUILD) ./utils/run-coverage

###############################################################################
# CI/CD
###############################################################################

.PHONY: cd ci version

## checks that we can get the version
version: image
	docker run --rm $(BUILD_IMAGE):latest-$(ARCH) calico-typha --version

## Builds the code and runs all tests.
ci: image-all version static-checks ut
ifeq (,$(filter k8sfv-test, $(EXCEPT)))
	@$(MAKE) k8sfv-test
endif

## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(BRANCH_NAME) EXCLUDEARCH="$(EXCLUDEARCH)"
	$(MAKE) tag-images-all push-all push-manifests push-non-manifests IMAGETAG=$(shell git describe --tags --dirty --always --long) EXCLUDEARCH="$(EXCLUDEARCH)"

k8sfv-test: image
	cd .. && git clone https://github.com/projectcalico/felix.git && cd felix; \
	[ ! -e ../typha/semaphore-felix-branch ] || git checkout $(cat ../typha/semaphore-felix-branch); \
	JUST_A_MINUTE=true USE_TYPHA=true FV_TYPHAIMAGE=$(BUILD_IMAGE):latest TYPHA_VERSION=latest $(MAKE) k8sfv-test

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
	$(MAKE) tag-images-all RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) tag-images-all RELEASE=true IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	docker run --rm $(BUILD_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep $(VERSION) || ( echo "Reported version:" `docker run --rm $(BUILD_IMAGE):$(VERSION)-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/$(BUILD_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/$(BUILD_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )

	# TODO: Some sort of quick validation of the produced binaries.

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	echo "" >> release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push the git tag.
	git push origin $(VERSION)

	# Push images.
	$(MAKE) push-all push-manifests push-non-manifests RELEASE=true IMAGETAG=$(VERSION)

	@echo "Finalize the GitHub release based on the pushed tag."
	@echo "Attach the $(DIST)/calico-typha-amd64 binary."
	@echo ""
	@echo "  https://$(PACKAGE_NAME)/releases/tag/$(VERSION)"
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
	if ! docker run $(BUILD_IMAGE):latest-$(ARCH) calico-typha --version | grep '$(VERSION)'; then echo "Reported version:" `docker run $(BUILD_IMAGE):latest-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(BUILD_IMAGE):latest-$(ARCH) calico-typha --version | grep '$(VERSION)'; then echo "Reported version:" `docker run quay.io/$(BUILD_IMAGE):latest-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push-all push-manifests push-non-manifests RELEASE=true IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifeq ($(GIT_COMMIT),<unknown>)
	$(error git commit ID could not be determined, releases must be done from a git working copy)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: ut-no-cover
ut-no-cover: vendor/.up-to-date $(SRC_FILES)
	@echo Running Go UTs without coverage.
	$(DOCKER_RUN) $(LOCAL_BUILD_MOUNTS) $(CALICO_BUILD) ginkgo -r $(GINKGO_OPTIONS)

.PHONY: ut-watch
ut-watch: vendor/.up-to-date $(SRC_FILES)
	@echo Watching go UTs for changes...
	$(DOCKER_RUN) $(LOCAL_BUILD_MOUNTS) $(CALICO_BUILD) ginkgo watch -r $(GINKGO_OPTIONS)

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

bin/calico-typha.transfer-url: bin/calico-typha-$(ARCH)
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'curl --upload-file bin/calico-typha-$(ARCH) https://transfer.sh/calico-typha > $@'

# Install or update the tools used by the build
.PHONY: update-tools
update-tools:
	go get -u github.com/Masterminds/glide
	go get -u github.com/onsi/ginkgo/ginkgo

help:
	@echo "Typha Makefile"
	@echo
	@echo "Dependencies: docker 1.12+; go 1.8+"
	@echo
	@echo "For any target, set ARCH=<target> to build for a given target."
	@echo "For example, to build for arm64:"
	@echo
	@echo "  make build ARCH=arm64"
	@echo
	@echo "Initial set-up:"
	@echo
	@echo "  make update-tools  Update/install the go build dependencies."
	@echo
	@echo "Builds:"
	@echo
	@echo "  make all           Build all the binary packages."
	@echo "  make image         Build $(BUILD_IMAGE) docker image."
	@echo
	@echo "Tests:"
	@echo
	@echo "  make ut                Run UTs."
	@echo "  make go-cover-browser  Display go code coverage in browser."
	@echo
	@echo "Maintenance:"
	@echo
	@echo "  make update-vendor  Update the vendor directory with new "
	@echo "                      versions of upstream packages.  Record results"
	@echo "                      in glide.lock."
	@echo "  make go-fmt        Format our go code."
	@echo "  make clean         Remove binary files."
	@echo "-----------------------------------------"
	@echo "ARCH (target):          $(ARCH)"
	@echo "BUILDARCH (host):       $(BUILDARCH)"
	@echo "CALICO_BUILD:     $(CALICO_BUILD)"
	@echo "-----------------------------------------"
