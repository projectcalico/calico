include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/typha

RELEASE_REGISTRIES    ?= gcr.io/projectcalico-org eu.gcr.io/projectcalico-org asia.gcr.io/projectcalico-org us.gcr.io/projectcalico-org
RELEASE_BRANCH_PREFIX ?= release
DEV_TAG_SUFFIX        ?= 0.dev

# If this is a release, also tag and push additional images.
ifeq ($(RELEASE),true)
TYPHA_IMAGE    ?=typha
DEV_REGISTRIES ?=quay.io/calico calico $(RELEASE_REGISTRIES)
else
TYPHA_IMAGE    ?=calico/typha
DEV_REGISTRIES ?=quay.io docker.io
endif

BUILD_IMAGES   ?=$(TYPHA_IMAGE)

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

# Add in local static-checks
LOCAL_CHECKS=check-boring-ssl

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

###############################################################################

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

# All Typha go files.
SRC_FILES:=$(shell find . $(foreach dir,$(NON_TYPHA_DIRS),-path ./$(dir) -prune -o) -type f -name '*.go' -print)

.PHONY: clean
clean:
	rm -rf .go-pkg-cache \
		bin \
		docker-image/bin \
		build \
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

bin/calico-typha: bin/calico-typha-$(ARCH)
	ln -f bin/calico-typha-$(ARCH) bin/calico-typha

bin/calico-typha-$(ARCH): $(SRC_FILES)
	mkdir -p bin
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
	    sh -c '$(GIT_CONFIG_SSH) go build -v -i -o $@ -v $(LDFLAGS) $(PACKAGE_NAME)/cmd/calico-typha'

bin/typha-client-$(ARCH): $(SRC_FILES)
	@echo Building typha client...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) \
	    sh -c '$(GIT_CONFIG_SSH) go build -v -i -o $@ -v $(LDFLAGS) "$(PACKAGE_NAME)/cmd/typha-client" && \
		( ldd $@ 2>&1 | grep -q -e "Not a valid dynamic program" \
		-e "not a dynamic executable" || \
		( echo "Error: bin/typha-client was not statically linked"; false ) )'

###############################################################################
# Building the image
###############################################################################
# Build the calico/typha docker image, which contains only typha.
.PHONY: $(TYPHA_IMAGE) $(TYPHA_IMAGE)-$(ARCH)
image: $(BUILD_IMAGES)

# Build the image for the target architecture
.PHONY: image-all
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

# Build the calico/typha docker image, which contains only Typha.
.PHONY: image $(TYPHA_IMAGE)
$(TYPHA_IMAGE): bin/calico-typha-$(ARCH) register
	rm -rf docker-image/bin
	mkdir -p docker-image/bin
	cp bin/calico-typha-$(ARCH) docker-image/bin/
	cp LICENSE docker-image/
	docker buildx build --platform linux/$(ARCH) -t $(TYPHA_IMAGE):latest-$(ARCH) --build-arg QEMU_IMAGE=$(CALICO_BUILD) --build-arg GIT_VERSION=$(GIT_VERSION) --file ./docker-image/Dockerfile.$(ARCH) docker-image --load
ifeq ($(ARCH),amd64)
	docker tag $(TYPHA_IMAGE):latest-$(ARCH) $(TYPHA_IMAGE):latest
endif

###############################################################################
# Unit Tests
###############################################################################
.PHONY: ut
ut combined.coverprofile: $(SRC_FILES)
	@echo Running Go UTs.
	$(DOCKER_RUN) $(CALICO_BUILD) ./utils/run-coverage

check-boring-ssl: bin/calico-typha-amd64
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		go tool nm bin/calico-typha-amd64 > bin/tags.txt && grep '_Cfunc__goboringcrypto_' bin/tags.txt 1> /dev/null
	-rm -f bin/tags.txt

###############################################################################
# CI/CD
###############################################################################
.PHONY: cd ci version
version: image
	docker run --rm $(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version

ci: mod-download image-all version static-checks ut
ifeq (,$(filter k8sfv-test, $(EXCEPT)))
	@$(MAKE) k8sfv-test
endif

## Deploys images to registry
cd: cd-common

fv: k8sfv-test

k8sfv-test: image
	$(MAKE) -C ../felix JUST_A_MINUTE=true USE_TYPHA=true FV_TYPHAIMAGE=$(TYPHA_IMAGE):latest TYPHA_VERSION=latest k8sfv-test

st:
	@echo "No STs available."

###############################################################################
# Release
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
	$(MAKE) image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	docker run --rm $(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep $(VERSION) || ( echo "Reported version:" `docker run --rm $(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/$(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/$(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )

	# TODO: Some sort of quick validation of the produced binaries.

## Generates release notes based on commits in this version.
release-notes: release-prereqs
	mkdir -p dist
	echo "# Changelog" > release-notes-$(VERSION)
	echo "" >> release-notes-$(VERSION)
	sh -c "git cherry -v $(PREVIOUS_RELEASE) | cut '-d ' -f 2- | sed 's/^/- /' >> release-notes-$(VERSION)"

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs
	# Push images.
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=true CONFIRM=true

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
	if ! docker run $(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version | grep '$(VERSION)'; then echo "Reported version:" `docker run $(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version | grep '$(VERSION)'; then echo "Reported version:" `docker run quay.io/$(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push-images-to-registries push-manifests RELEASE=true IMAGETAG=latest RELEASE=true CONFIRM=true

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifeq ($(GIT_COMMIT),<unknown>)
	$(error git commit ID could not be determined, releases must be done from a git working copy)
endif

###############################################################################
# Developer helper scripts (not used by build or test)
###############################################################################
.PHONY: ut-no-cover
ut-no-cover: $(SRC_FILES)
	@echo Running Go UTs without coverage.
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -r

.PHONY: ut-watch
ut-watch: $(SRC_FILES)
	@echo Watching go UTs for changes...
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo watch -r

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
	go get -u github.com/onsi/ginkgo/ginkgo
