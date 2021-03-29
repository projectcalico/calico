PACKAGE_NAME    ?= github.com/projectcalico/apiserver
GO_BUILD_VER    ?= v0.49
GOMOD_VENDOR    := false
GIT_USE_SSH      = true
LOCAL_CHECKS     = lint-cache-dir goimports check-copyright
# Used by Makefile.common
LIBCALICO_REPO   = github.com/projectcalico/libcalico-go
# Used only when doing local build
LOCAL_LIBCALICO  = /go/src/github.com/projectcalico/libcalico-go
# Used so semaphore commits generated files when pins are updated
EXTRA_FILES_TO_COMMIT=*_generated.go *_generated.*.go

SEMAPHORE_PROJECT_ID?=$(SEMAPHORE_API_SERVER_PROJECT_ID)

# Used so semaphore can trigger the update pin pipelines in projects that have this project as a dependency.
SEMAPHORE_AUTO_PIN_UPDATE_PROJECT_IDS=$(SEMAPHORE_LMA_PROJECT_ID) $(SEMAPHORE_COMPLIANCE_PROJECT_ID) \
	 $(SEMAPHORE_ES_PROXY_IMAGE_PROJECT_ID) $(SEMAPHORE_INTRUSION_DETECTION_PROJECT_ID)

build: image

##############################################################################
# Download and include Makefile.common before anything else
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
##############################################################################
MAKE_BRANCH?=$(GO_BUILD_VER)
MAKE_REPO?=https://raw.githubusercontent.com/projectcalico/go-build/$(MAKE_BRANCH)

Makefile.common: Makefile.common.$(MAKE_BRANCH)
	cp "$<" "$@"
Makefile.common.$(MAKE_BRANCH):
	# Clean up any files downloaded from other branches so they don't accumulate.
	rm -f Makefile.common.*
	curl --fail $(MAKE_REPO)/Makefile.common -o "$@"

# Allow libcalico-go to be mapped into the build container.
# Please note, this will change go.mod.
ifdef LIBCALICOGO_PATH
EXTRA_DOCKER_ARGS += -v $(LIBCALICOGO_PATH):$(LOCAL_LIBCALICO):ro
endif

EXTRA_DOCKER_ARGS += -e GOLANGCI_LINT_CACHE=/lint-cache -v $(CURDIR)/.lint-cache:/lint-cache:rw \
				 -v $(CURDIR)/hack/boilerplate:/go/src/k8s.io/kubernetes/hack/boilerplate:rw

include Makefile.common

###############################################################################
K8S_VERSION = v1.16.3
BINDIR ?= bin
CONTAINER_NAME = quay.io/calico/apiserver
BUILD_DIR ?= build
TOP_SRC_DIRS = pkg cmd
SRC_DIRS = $(shell sh -c "find $(TOP_SRC_DIRS) -name \\*.go \
                   -exec dirname {} \\; | sort | uniq")
TEST_DIRS ?= $(shell sh -c "find $(TOP_SRC_DIRS) -name \\*_test.go \
                    -exec dirname {} \\; | sort | uniq")

ifeq ($(shell uname -s),Darwin)
	STAT = stat -f '%c %N'
else
	STAT = stat -c '%Y %n'
endif

K8SAPISERVER_GO_FILES = $(shell find $(SRC_DIRS) -name \*.go -exec $(STAT) {} \; \
                   | sort -r | head -n 1 | sed "s/.* //")

ifdef UNIT_TESTS
UNIT_TEST_FLAGS = -run $(UNIT_TESTS) -v
endif

APISERVER_VERSION?=$(shell git describe --tags --dirty --always --abbrev=12)
APISERVER_BUILD_DATE?=$(shell date -u +'%FT%T%z')
APISERVER_GIT_REVISION?=$(shell git rev-parse --short HEAD)
APISERVER_GIT_DESCRIPTION?=$(shell git describe --tags)

VERSION_FLAGS = -X $(PACKAGE_NAME)/cmd/apiserver/server.VERSION=$(APISERVER_VERSION) \
	-X $(PACKAGE_NAME)/cmd/apiserver/server.BUILD_DATE=$(APISERVER_BUILD_DATE) \
	-X $(PACKAGE_NAME)/cmd/apiserver/server.GIT_DESCRIPTION=$(APISERVER_GIT_DESCRIPTION) \
	-X $(PACKAGE_NAME)/cmd/apiserver/server.GIT_REVISION=$(APISERVER_GIT_REVISION)

BUILD_LDFLAGS = -ldflags "$(VERSION_FLAGS)"
RELEASE_LDFLAGS = -ldflags "$(VERSION_FLAGS) -s -w"
KUBECONFIG_DIR? = /etc/kubernetes/admin.conf

###############################################################################
# Managing the upstream library pins
#
# If you're updating the pins with a non-release branch checked out,
# set PIN_BRANCH to the parent branch, e.g.:
#
#     PIN_BRANCH=release-v2.5 make update-pins
#        - or -
#     PIN_BRANCH=master make update-pins
#
###############################################################################

## Guard so we don't run this on osx because of ssh-agent to docker forwarding bug
guard-ssh-forwarding-bug:
	@if [ "$(shell uname)" = "Darwin" ]; then \
		echo "ERROR: This target requires ssh-agent to docker key forwarding and is not compatible with OSX/Mac OS"; \
		echo "$(MAKECMDGOALS)"; \
		exit 1; \
	fi;

## Update dependency pins
update-pins: guard-ssh-forwarding-bug update-libcalico-pin

###############################################################################
# This section contains the code generation stuff
###############################################################################
.generate_execs: lint-cache-dir\
	$(BINDIR)/defaulter-gen \
	$(BINDIR)/deepcopy-gen \
	$(BINDIR)/conversion-gen \
	$(BINDIR)/client-gen \
	$(BINDIR)/lister-gen \
	$(BINDIR)/informer-gen \
	$(BINDIR)/openapi-gen 
	touch $@

$(BINDIR)/deepcopy-gen:
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/deepcopy-gen"

$(BINDIR)/client-gen:
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/client-gen"

$(BINDIR)/lister-gen:
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/lister-gen"

$(BINDIR)/informer-gen:
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/informer-gen"

$(BINDIR)/defaulter-gen: 
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/defaulter-gen"

$(BINDIR)/conversion-gen: 
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/conversion-gen"

$(BINDIR)/openapi-gen:
	$(DOCKER_GO_BUILD) sh -c "GOBIN=/go/src/$(PACKAGE_NAME)/$(BINDIR) go install k8s.io/code-generator/cmd/openapi-gen"

# Regenerate all files if the gen exes changed or any "types.go" files changed
.PHONY: gen-files
gen-files .generate_files: lint-cache-dir .generate_execs clean-generated
	# Generate defaults
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) $(BINDIR)/defaulter-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--extra-peer-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico" \
		--extra-peer-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--output-file-base "zz_generated.defaults"'
	# Generate deep copies
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) $(BINDIR)/deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--bounding-dirs $(PACKAGE_NAME) \
		--output-file-base zz_generated.deepcopy'
	# Generate conversions
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) $(BINDIR)/conversion-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3" \
		--output-file-base zz_generated.conversion'
	# generate all pkg/client contents
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) $(BUILD_DIR)/update-client-gen.sh'
	# generate openapi
	$(DOCKER_RUN) $(CALICO_BUILD) \
	   sh -c '$(GIT_CONFIG_SSH) $(BINDIR)/openapi-gen \
		--v 1 --logtostderr \
		--go-header-file "/go/src/$(PACKAGE_NAME)/hack/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/projectcalico/v3,k8s.io/api/core/v1,k8s.io/api/networking/v1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/version,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/util/intstr,github.com/projectcalico/libcalico-go/lib/apis/v3,github.com/projectcalico/libcalico-go/lib/apis/v1,github.com/projectcalico/libcalico-go/lib/numorstring" \
		--output-package "$(PACKAGE_NAME)/pkg/openapi"'
	touch .generate_files
	$(MAKE) fix

.PHONY: gen-swagger
gen-swagger: $(BINDIR)/apiserver run-kubernetes-server
	$(BINDIR)/apiserver --secure-port 5443 \
		--print-swagger \
		--kubeconfig test/test-apiserver-kubeconfig.conf --swagger-file-path artifacts/swagger

###############################################################################
# ensure we have a real imagetag
###############################################################################
imagetag:
ifndef IMAGETAG
	$(error IMAGETAG is undefined - run using make <target> IMAGETAG=X.Y.Z)
endif

tag-image: imagetag calico/apiserver
	docker tag calico/apiserver:latest $(CONTAINER_NAME):$(IMAGETAG)

push-image: imagetag tag-image
	docker push $(CONTAINER_NAME):$(IMAGETAG)

###############################################################################
# Static checks
###############################################################################
.PHONY: static-checks

## Perform static checks on the code.
# TODO: re-enable these linters !
LINT_ARGS := --disable gosimple,govet,structcheck,errcheck,goimports,unused,ineffassign,staticcheck,deadcode,typecheck --timeout 5m

###############################################################################
# CI/CD
###############################################################################
.PHONY: ci
## Run what CI runs
ci: clean check-generated-files static-checks calico/apiserver fv ut

## Deploys images to registry
cd:
ifndef CONFIRM
	$(error CONFIRM is undefined - run using make <target> CONFIRM=true)
endif
ifndef BRANCH_NAME
	$(error BRANCH_NAME is undefined - run using make <target> BRANCH_NAME=var or set an environment variable)
endif
	$(MAKE) push-image IMAGETAG=${BRANCH_NAME}
	$(MAKE) push-image IMAGETAG=${GIT_VERSION}

## Check if generated files are out of date
.PHONY: check-generated-files
check-generated-files: .generate_files
	if (git describe --tags --dirty | grep -c dirty >/dev/null); then \
	  echo "Generated files are out of date."; \
	  false; \
	else \
	  echo "Generated files are up to date."; \
	fi

# This section builds the output binaries.
# Some will have dedicated targets to make it easier to type, for example
# "apiserver" instead of "$(BINDIR)/apiserver".
#########################################################################
$(BINDIR)/apiserver: .generate_files $(K8SAPISERVER_GO_FILES)
ifndef RELEASE_BUILD
	$(eval LDFLAGS:=$(RELEASE_LDFLAGS))
else
	$(eval LDFLAGS:=$(BUILD_LDFLAGS))
endif
	@echo Building k8sapiserver...
	mkdir -p bin
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -v -i -o $@ -v $(LDFLAGS) "$(PACKAGE_NAME)/cmd/apiserver" && \
		( ldd $(BINDIR)/apiserver 2>&1 | \
	        grep -q -e "Not a valid dynamic program" -e "not a dynamic executable" || \
		( echo "Error: $(BINDIR)/apiserver was not statically linked"; false ) )'

$(BINDIR)/filecheck: $(K8SAPISERVER_GO_FILES)
ifndef RELEASE_BUILD
	$(eval LDFLAGS:=$(RELEASE_LDFLAGS))
else
	$(eval LDFLAGS:=$(BUILD_LDFLAGS))
endif
	@echo Building filecheck...
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) go build -v -i -o $@ -v $(LDFLAGS) "$(PACKAGE_NAME)/cmd/filecheck" && \
		( ldd $(BINDIR)/filecheck 2>&1 | \
	        grep -q -e "Not a valid dynamic program" -e "not a dynamic executable" || \
		( echo "Error: $(BINDIR)/filecheck was not statically linked"; false ) )'

# Build cnx-apiserver docker image.
# Recursive make calico/apiserver forces make to rebuild dependencies again
image:
	make calico/apiserver

# Build the calico/apiserver docker image.
.PHONY: calico/apiserver
calico/apiserver: .generate_files $(BINDIR)/apiserver $(BINDIR)/filecheck
	rm -rf docker-image/bin
	mkdir -p docker-image/bin
	cp $(BINDIR)/apiserver docker-image/bin/
	cp $(BINDIR)/filecheck docker-image/bin/
	docker build --pull -t calico/apiserver --file ./docker-image/Dockerfile.$(ARCH) docker-image

.PHONY: lint-cache-dir
lint-cache-dir:
	mkdir -p $(CURDIR)/.lint-cache

.PHONY: ut 
ut: lint-cache-dir run-etcd
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c '$(GIT_CONFIG_SSH) ETCD_ENDPOINTS="http://127.0.0.1:2379" DATASTORE_TYPE="etcdv3" go test $(UNIT_TEST_FLAGS) \
			$(addprefix $(PACKAGE_NAME)/,$(TEST_DIRS))'

.PHONY: st
st:
	@echo "Nothing to do for $@"

.PHONY: check-copyright
check-copyright:
	@hack/check-copyright.sh

config/crd: mod-download
	mkdir -p config/crd
	$(DOCKER_GO_BUILD) sh -c ' \
		cp -r `go list -m -f "{{.Dir}}" github.com/projectcalico/libcalico-go`/config/crd/* config/crd; \
		chmod +w config/crd/*'

## Run etcd as a container (calico-etcd)
run-etcd: stop-etcd
	docker run --detach \
	--net=host \
	--entrypoint=/usr/local/bin/etcd \
	--name calico-etcd quay.io/coreos/etcd:v3.1.7 \
	--advertise-client-urls "http://$(LOCAL_IP_ENV):2379,http://127.0.0.1:2379,http://$(LOCAL_IP_ENV):4001,http://127.0.0.1:4001" \
	--listen-client-urls "http://0.0.0.0:2379,http://0.0.0.0:4001"

## Stop the etcd container (calico-etcd)
stop-etcd:
	-docker rm -f calico-etcd

GITHUB_TEST_INTEGRATION_URI := https://raw.githubusercontent.com/kubernetes/kubernetes/v1.16.4/hack/lib

hack-lib:
	mkdir -p hack/lib/
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/init.sh -o hack/lib/init.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/util.sh -o hack/lib/util.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/logging.sh -o hack/lib/logging.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/version.sh -o hack/lib/version.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/golang.sh -o hack/lib/golang.sh
	curl -s --fail $(GITHUB_TEST_INTEGRATION_URI)/etcd.sh -o hack/lib/etcd.sh

## Run a local kubernetes server with API via hyperkube
run-kubernetes-server: config/crd run-etcd stop-kubernetes-server
	# Run a Kubernetes apiserver using Docker.
	docker run \
		--net=host --name st-apiserver \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		kube-apiserver \
			--bind-address=0.0.0.0 \
			--insecure-bind-address=0.0.0.0 \
			--etcd-servers=http://127.0.0.1:2379 \
			--admission-control=NamespaceLifecycle,LimitRanger,DefaultStorageClass,ResourceQuota \
			--authorization-mode=RBAC \
			--service-cluster-ip-range=10.101.0.0/16 \
			--v=10 \
			--logtostderr=true

	# Wait until we can configure a cluster role binding which allows anonymous auth.
	while ! docker exec st-apiserver kubectl create clusterrolebinding anonymous-admin --clusterrole=cluster-admin --user=system:anonymous; do echo "Trying to create ClusterRoleBinding"; sleep 2; done

	# And run the controller manager.
	docker run \
		--net=host --name st-controller-manager \
		--detach \
		gcr.io/google_containers/hyperkube-amd64:${K8S_VERSION} \
		/hyperkube controller-manager \
			--master=127.0.0.1:8080 \
			--min-resync-period=3m \
			--allocate-node-cidrs=true \
			--cluster-cidr=10.10.0.0/16 \
			--v=5

	# Create CustomResourceDefinition (CRD) for Calico resources
	# from the manifest crds.yaml
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		lachlanevenson/k8s-kubectl:${K8S_VERSION} \
		--server=http://127.0.0.1:8080 \
		apply -f /manifests/config/crd/

	# Create a Node in the API for the tests to use.
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		lachlanevenson/k8s-kubectl:${K8S_VERSION} \
		--server=http://127.0.0.1:8080 \
		apply -f /manifests/test/mock-node.yaml

	# Create Namespaces required by namespaced Calico `NetworkPolicy`
	# tests from the manifests namespaces.yaml.
	docker run \
		--net=host \
		--rm \
		-v  $(CURDIR):/manifests \
		lachlanevenson/k8s-kubectl:${K8S_VERSION} \
		--server=http://127.0.0.1:8080 \
		apply -f /manifests/test/namespaces.yaml

## Stop the local kubernetes server
stop-kubernetes-server:
	# Delete the cluster role binding.
	-docker exec st-apiserver kubectl delete clusterrolebinding anonymous-admin

	# Stop master components.
	-docker rm -f st-apiserver st-controller-manager


# TODO(doublek): Add fv-etcd back to fv. It is currently disabled because profiles behavior is broken.
# Profiles should be disallowed from being created for both etcd and kdd mode. However we are allowing
# profiles to be created in etcd and disallow in kdd. This has the test incorrect for etcd and running
# for kdd.
.PHONY: fv
fv: fv-kdd

.PHONY: fv-etcd
fv-etcd: run-kubernetes-server hack-lib
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c 'ETCD_ENDPOINTS="http://127.0.0.1:2379" DATASTORE_TYPE="etcdv3" test/integration.sh'

.PHONY: fv-kdd
fv-kdd: run-kubernetes-server hack-lib
	$(DOCKER_RUN) $(CALICO_BUILD) \
		sh -c 'K8S_API_ENDPOINT="http://127.0.0.1:8080" DATASTORE_TYPE="kubernetes" test/integration.sh'

.PHONY: clean
clean: clean-bin clean-build-image clean-hack-lib
	rm -rf .lint-cache Makefile.common*

clean-build-image:
	docker rmi -f calico/apiserver > /dev/null 2>&1 || true

clean-generated:
	rm -f .generate_files
	find $(TOP_SRC_DIRS) -name zz_generated* -exec rm {} \;
	# rollback changes to the generated clientset directories
	# find $(TOP_SRC_DIRS) -type d -name *_generated -exec rm -rf {} \;
	rm -rf pkg/client/clientset_generated pkg/client/informers_generated pkg/client/listers_generated

clean-bin:
	rm -rf $(BINDIR) \
	    .generate_execs \
	    docker-image/bin

clean-hack-lib:
	rm -rf hack/lib/

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
# Check that the correct code is checked out.
ifneq ($(VERSION), $(GIT_VERSION))
	$(error Attempt to build $(VERSION) from $(GIT_VERSION))
endif

	$(MAKE) image
	$(MAKE) tag-image IMAGETAG=$(VERSION)
	# Generate the `latest` images.
	$(MAKE) tag-image IMAGETAG=latest

## Verifies the release artifacts produces by `make release-build` are correct.
release-verify: release-prereqs
	# Check the reported version is correct for each release artifact.
	if ! docker run calico/apiserver | grep 'Version:\s*$(VERSION)$$'; then \
	  echo "Reported version:" `docker run calico/apiserver` "\nExpected version: $(VERSION)"; \
	  false; \
	else \
	  echo "Version check passed\n"; \
	fi

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
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=$(VERSION)

	@echo "Finalize the GitHub release based on the pushed tag."
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
	$(MAKE) push-all push-manifests push-non-manifests IMAGETAG=latest

# release-prereqs checks that the environment is configured properly to create a release.
release-prereqs:
ifndef VERSION
	$(error VERSION is undefined - run using make release VERSION=vX.Y.Z)
endif
ifdef LOCAL_BUILD
	$(error LOCAL_BUILD must not be set for a release)
endif

###############################################################################
# Utils
###############################################################################
# this is not a linked target, available for convenience.
.PHONY: tidy
## 'tidy' mods.
tidy:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c '$(GIT_CONFIG_SSH) go mod tidy'
