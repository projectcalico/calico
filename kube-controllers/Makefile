include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/kube-controllers

# Name of the images.
# e.g., <registry>/<name>:<tag>
KUBE_CONTROLLERS_IMAGE  ?=kube-controllers
FLANNEL_MIGRATION_IMAGE ?=flannel-migration-controller

BUILD_IMAGES            ?=$(KUBE_CONTROLLERS_IMAGE) $(FLANNEL_MIGRATION_IMAGE)

# Add in local static-checks
LOCAL_CHECKS=check-boring-ssl

###############################################################################
# Download and include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

include ../lib.Makefile

SRC_FILES=cmd/kube-controllers/main.go $(shell find pkg -name '*.go') $(shell find ../libcalico-go -name '*.go')

# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
ifeq ($(ARCH), $(filter $(ARCH),amd64))
CGO_ENABLED=1
else
CGO_ENABLED=0
endif

###############################################################################

## Removes all build artifacts.
clean:
	# Clean .created files which indicate images / releases have been built.
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf .go-pkg-cache bin image.created-$(ARCH) build report/*.xml release-notes-*
	-docker rmi $(KUBE_CONTROLLERS_IMAGE)
	-docker rmi $(KUBE_CONTROLLERS_IMAGE):latest-amd64
	-docker rmi $(FLANNEL_MIGRATION_IMAGE)
	-docker rmi $(FLANNEL_MIGRATION_IMAGE):latest-amd64
	rm -f tests/fv/fv.test
	rm -f report/*.xml

###############################################################################
# Building the binary
###############################################################################
build: bin/kube-controllers-linux-$(ARCH) bin/check-status-linux-$(ARCH)
build-all: $(addprefix sub-build-,$(VALIDARCHES))
sub-build-%:
	$(MAKE) build ARCH=$*

bin/kube-controllers-linux-$(ARCH): $(SRC_FILES)
	$(DOCKER_RUN) \
	  -e CGO_ENABLED=$(CGO_ENABLED) \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  $(CALICO_BUILD) go build -v -o bin/kube-controllers-$(BUILDOS)-$(ARCH) -ldflags "-X main.VERSION=$(GIT_VERSION)" ./cmd/kube-controllers/

bin/check-status-linux-$(ARCH): $(SRC_FILES)
	$(DOCKER_RUN) \
	  -e CGO_ENABLED=$(CGO_ENABLED) \
	  -v $(CURDIR)/bin:/go/src/$(PACKAGE_NAME)/bin \
	  $(CALICO_BUILD) go build -v -o bin/check-status-$(BUILDOS)-$(ARCH) -ldflags "-X main.VERSION=$(GIT_VERSION)" ./cmd/check-status/

bin/kubectl-$(ARCH):
	wget https://storage.googleapis.com/kubernetes-release/release/$(KUBECTL_VERSION)/bin/linux/$(subst armv7,arm,$(ARCH))/kubectl -O $@
	chmod +x $@

###############################################################################
# Building the image
###############################################################################
## Builds the controller binary and docker image.
image: image.created-$(ARCH)
image-all: $(addprefix sub-image-,$(VALIDARCHES))
sub-image-%:
	$(MAKE) image ARCH=$*

image.created-$(ARCH): bin/kube-controllers-linux-$(ARCH) bin/check-status-linux-$(ARCH) bin/kubectl-$(ARCH)
	$(DOCKER_BUILD) -t $(KUBE_CONTROLLERS_IMAGE):latest-$(ARCH) -f Dockerfile.$(ARCH) . --load
	$(DOCKER_BUILD) -t $(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) -f docker-images/flannel-migration/Dockerfile.$(ARCH) . --load
	$(MAKE) retag-build-images-with-registries VALIDARCHES=$(ARCH) IMAGETAG=latest
	touch $@

###############################################################################
# Static checks
###############################################################################
# Make sure that a copyright statement exists on all go files.
check-copyright:
	./check-copyrights.sh

check-boring-ssl: bin/kube-controllers-linux-amd64
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) $(CALICO_BUILD) \
		go tool nm bin/kube-controllers-linux-amd64 > bin/tags.txt && grep '_Cfunc__goboringcrypto_' bin/tags.txt 1> /dev/null
	-rm -f bin/tags.txt

###############################################################################
# Tests
###############################################################################
## Run the unit tests in a container.
ut:
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) sh -c 'WHAT=$(WHAT) SKIP=$(SKIP) GINKGO_ARGS=$(GINKGO_ARGS) ./run-uts'

.PHONY: fv
## Build and run the FV tests.
fv: tests/fv/fv.test image
	@echo Running Go FVs.
	cd tests/fv && ETCD_IMAGE=$(ETCD_IMAGE) \
		KUBE_IMAGE=$(CALICO_BUILD) \
		CONTAINER_NAME=$(KUBE_CONTROLLERS_IMAGE):latest-$(ARCH) \
		MIGRATION_CONTAINER_NAME=$(FLANNEL_MIGRATION_IMAGE):latest-$(ARCH) \
		PRIVATE_KEY=`pwd`/private.key \
		CRDS=$(CURDIR)/../libcalico-go/config/crd \
		CERTS_PATH=$(CERTS_PATH) \
		./fv.test $(GINKGO_ARGS) -ginkgo.slow-spec-threshold 30

tests/fv/fv.test: $(shell find ./tests -type f -name '*.go' -print)
	# We pre-build the test binary so that we can run it outside a container and allow it
	# to interact with docker.
	$(DOCKER_RUN) $(CALICO_BUILD) go test ./tests/fv -c --tags fvtests -o tests/fv/fv.test

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download image-all static-checks ut fv

###############################################################################
# CD
###############################################################################
.PHONY: cd
## Deploys images to registry
cd: cd-common

###############################################################################
# Release
###############################################################################
## Produces a clean build of release artifacts at the specified version.
release-build: .release-$(VERSION).created 
.release-$(VERSION).created:
	$(MAKE) clean image-all RELEASE=true
	$(MAKE) retag-build-images-with-registries IMAGETAG=$(VERSION) RELEASE=true
	# Generate the `latest` images.
	$(MAKE) retag-build-images-with-registries IMAGETAG=latest RELEASE=true
	touch $@

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run $(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):$(VERSION)-$(ARCH) --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi

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
	if ! docker run $(KUBE_CONTROLLERS_IMAGE):latest --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run $(KUBE_CONTROLLERS_IMAGE):latest --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	if ! docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):latest --version | grep '^$(VERSION)$$'; then echo "Reported version:" `docker run quay.io/$(KUBE_CONTROLLERS_IMAGE):latest --version` "\nExpected version: $(VERSION)"; false; else echo "\nVersion check passed\n"; fi
	$(MAKE) push-images-to-registries push-manifests IMAGETAG=latest RELEASE=$(RELEASE) CONFIRM=$(CONFIRM)
