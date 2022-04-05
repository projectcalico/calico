include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/typha

# Name of the images.
# e.g., <registry>/<name>:<tag>
TYPHA_IMAGE    ?=typha
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
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
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
	$(DOCKER_BUILD) -t $(TYPHA_IMAGE):latest-$(ARCH) --file ./docker-image/Dockerfile.$(ARCH) docker-image --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest

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
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created 
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=$(VERSION)
	$(MAKE) retag-build-images-with-registries RELEASE=true IMAGETAG=latest
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	docker run --rm $(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep $(VERSION) || ( echo "Reported version:" `docker run --rm $(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)" && exit 1 )
	docker run --rm quay.io/$(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep $(VERSION) || ( echo "Reported version:" `docker run --rm quay.io/$(TYPHA_IMAGE):$(VERSION)-$(ARCH) calico-typha --version | grep -x $(VERSION)` "\nExpected version: $(VERSION)" && exit 1 )

	# TODO: Some sort of quick validation of the produced binaries.

## Pushes a github release and release artifacts produced by `make release-build`.
release-publish: release-prereqs .release-$(VERSION).published
.release-$(VERSION).published:
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=$(VERSION) RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
	touch $@

# WARNING: Only run this target if this release is the latest stable release. Do NOT
# run this target for alpha / beta / release candidate builds, or patches to earlier Calico versions.
## Pushes `latest` release images. WARNING: Only run this for latest stable releases.
release-publish-latest: release-prereqs
	# Check latest versions match.
	if ! docker run $(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version | grep '$(VERSION)'; then echo "Reported version:" `docker run $(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version | grep '$(VERSION)'; then echo "Reported version:" `docker run quay.io/$(TYPHA_IMAGE):latest-$(ARCH) calico-typha --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)

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
