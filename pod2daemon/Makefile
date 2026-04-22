include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/pod2daemon

# The node-driver-registrar binary is the only standalone binary produced by
# pod2daemon. It is cloned from upstream and bundled into the calico/calico
# image by cmd/calico/Makefile. The CSI driver and flex volume driver are
# compiled into the main calico binary as subcommands.
REGISTRAR_IMAGE ?= node-driver-registrar

###############################################################################
# Download and include ../lib.Makefile before anything else
###############################################################################

include ../lib.Makefile

###############################################################################

## SRC_FILES is auto-populated from deps.txt by lib.Makefile.

.PHONY: clean
## Clean enough that a new release build will be clean
clean:
	find . -name '.*.created*' -type f -delete
	find . -name '.*.published*' -type f -delete
	rm -rf report/
	rm -rf bin
	$(MAKE) clean-registrar

###############################################################################
# Building the binary
###############################################################################
BINDIR=bin

.PHONY: build
## Build the node-driver-registrar binary for the current architecture.
build: $(BINDIR)/node-driver-registrar-$(ARCH)

protobuf proto/udsver.pb.go: proto/udsver.proto
	$(DOCKER_RUN) -v $(CURDIR)/proto:/proto:rw \
		$(CALICO_BUILD) sh -c 'protoc --proto_path=/proto --go_out=/proto --go-grpc_out=. --go_opt=paths=source_relative udsver.proto'
	# Make sure the generated code won't cause a static-checks failure.
	$(MAKE) fix-changed

UPSTREAM_REGISTRAR_PROJECT ?= kubernetes-csi/$(REGISTRAR_IMAGE)
UPSTREAM_REGISTRAR_TAG     ?= f0fd46fc3fbdb6fe20fc2d2614631816b551a143 #https://github.com/kubernetes-csi/node-driver-registrar/commit/f0fd46fc3fbdb6fe20fc2d2614631816b551a143

REGISTRAR_TIGERA_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && \
	go build -tags $(TAGS) -buildvcs=false -v -o $(BINDIR)/csi-node-driver-registrar cmd/csi-node-driver-registrar/*.go"
REGISTRAR_UPSTREAM_BUILD_CMD="cd /go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT) && make build BUILD_PLATFORMS=$(BUILD_PLATFORMS)"

ifeq ($(ARCH), $(filter $(ARCH),amd64))
# We need CGO to leverage Boring SSL.  However, the cross-compile doesn't support CGO yet.
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
CGO_ENABLED=1
GOEXPERIMENT=""
else ifeq ($(ARCH), $(filter $(ARCH),arm64))
CGO_ENABLED=0
REGISTRAR_BUILD_CMD=$(REGISTRAR_TIGERA_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),ppc64le))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='linux ppc64le ppc64le'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),s390x))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='linux s390x s390x'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
else ifeq ($(ARCH), $(filter $(ARCH),win64))
# Note: We must use single quotes on BUILD_PLATFORMS since it is to be nested within another double-quoted string.
BUILD_PLATFORMS='windows amd64 amd64'
REGISTRAR_BUILD_CMD=$(REGISTRAR_UPSTREAM_BUILD_CMD)
endif

$(BINDIR)/node-driver-registrar-%: clone-registrar-upstream
	$(DOCKER_RUN) -e CGO_ENABLED=$(CGO_ENABLED) -e GOEXPERIMENT=$(GOEXPERIMENT) \
			-v $(REPO_ROOT)/pod2daemon/$(REGISTRAR_IMAGE):/go/src/github.com/$(UPSTREAM_REGISTRAR_PROJECT):rw \
			$(CALICO_BUILD) \
			/bin/bash -c $(REGISTRAR_BUILD_CMD)
			mv $(REGISTRAR_IMAGE)/$(BINDIR)/csi-node-driver-registrar $@

clone-registrar-upstream:
ifeq ("$(wildcard ./$(REGISTRAR_IMAGE))", "")
	@echo "Directory does not exist."
	git clone --depth 1 --single-branch https://github.com/$(UPSTREAM_REGISTRAR_PROJECT).git
else
	@echo "Upstream repo already cloned."
endif
	cd $(REGISTRAR_IMAGE) && \
	  git checkout $(UPSTREAM_REGISTRAR_TAG) || \
	  git fetch --tags origin $(UPSTREAM_REGISTRAR_TAG) && \
	  git checkout $(UPSTREAM_REGISTRAR_TAG)
	rm -rf ./$(REGISTRAR_IMAGE)/vendor

clean-registrar:
	rm -rf ./$(REGISTRAR_IMAGE)

###############################################################################
# UTs
###############################################################################
.PHONY: ut
## Run the tests in a container. Useful for CI, Mac dev
ut: $(SRC_FILES)
	mkdir -p report
	$(DOCKER_RUN) --privileged $(CALICO_BUILD) sh -c 'set -o pipefail && cd /go/src/$(PACKAGE_NAME) && go test -v ./... | go-junit-report > ./report/tests.xml'

fv st:
	@echo "No FVs or STs available"

###############################################################################
# CI
###############################################################################
.PHONY: ci
ci: clean mod-download build clean-registrar static-checks ut
