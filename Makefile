PACKAGE_NAME = github.com/projectcalico/calico

include metadata.mk
include lib.Makefile

DOCKER_RUN := mkdir -p ./.go-pkg-cache bin $(GOMOD_CACHE) && \
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

clean:
	$(MAKE) -C api clean
	$(MAKE) -C apiserver clean
	$(MAKE) -C app-policy clean
	$(MAKE) -C calicoctl clean
	$(MAKE) -C cni-plugin clean
	$(MAKE) -C confd clean
	$(MAKE) -C felix clean
	$(MAKE) -C kube-controllers clean
	$(MAKE) -C libcalico-go clean
	$(MAKE) -C node clean
	$(MAKE) -C pod2daemon clean
	$(MAKE) -C key-cert-provisioner clean
	$(MAKE) -C typha clean
	$(MAKE) -C release clean
	rm -rf ./bin

ci-preflight-checks:
	$(MAKE) check-go-mod
	$(MAKE) check-dockerfiles
	$(MAKE) check-language
	$(MAKE) check-ocp-no-crds
	$(MAKE) generate
	$(MAKE) fix-all
	$(MAKE) check-dirty

check-go-mod:
	$(DOCKER_GO_BUILD) ./hack/check-go-mod.sh

check-dockerfiles:
	./hack/check-dockerfiles.sh

check-language:
	./hack/check-language.sh

CRD_FILES_IN_OCP_DIR=$(shell grep "^kind: CustomResourceDefinition" manifests/ocp/* -l)
check-ocp-no-crds:
	@echo "Checking for files in  manifests/ocp with CustomResourceDefinitions"
	@if [ ! -z "$(CRD_FILES_IN_OCP_DIR)" ]; then echo "ERROR: manifests/ocp should not have any CustomResourceDefinitions, these files should be removed:"; echo "$(CRD_FILES_IN_OCP_DIR)"; exit 1; fi

protobuf:
	$(MAKE) -C app-policy protobuf
	$(MAKE) -C cni-plugin protobuf
	$(MAKE) -C felix protobuf
	$(MAKE) -C pod2daemon protobuf
	$(MAKE) -C goldmane protobuf

generate:
	$(MAKE) gen-semaphore-yaml
	$(MAKE) protobuf
	$(MAKE) -C lib gen-files
	$(MAKE) -C api gen-files
	$(MAKE) -C libcalico-go gen-files
	$(MAKE) -C felix gen-files
	$(MAKE) -C goldmane gen-files
	$(MAKE) gen-manifests
	$(MAKE) fix-changed

gen-manifests: bin/helm
	cd ./manifests && \
		OPERATOR_VERSION=$(OPERATOR_VERSION) \
		CALICO_VERSION=$(CALICO_VERSION) \
		./generate.sh

# Get operator CRDs from the operator repo, OPERATOR_BRANCH must be set
get-operator-crds: var-require-all-OPERATOR_BRANCH
	@echo ================================================================
	@echo === Pulling new operator CRDs from branch $(OPERATOR_BRANCH) ===
	@echo ================================================================
	cd ./charts/tigera-operator/crds/ && \
	for file in operator.tigera.io_*.yaml; do echo "downloading $$file from operator repo" && curl -fsSL https://raw.githubusercontent.com/tigera/operator/$(OPERATOR_BRANCH)/pkg/crds/operator/$${file%_crd.yaml}.yaml -o $${file}; done
	$(MAKE) fix-changed

gen-semaphore-yaml:
	cd .semaphore && ./generate-semaphore-yaml.sh

# Build the tigera-operator helm chart.
chart: bin/tigera-operator-$(GIT_VERSION).tgz
bin/tigera-operator-$(GIT_VERSION).tgz: bin/helm $(shell find ./charts/tigera-operator -type f)
	bin/helm package ./charts/tigera-operator \
	--destination ./bin/ \
	--version $(GIT_VERSION) \
	--app-version $(GIT_VERSION)

# Build all Calico images for the current architecture.
image:
	$(MAKE) -C pod2daemon image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C key-cert-provisioner image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C calicoctl image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C cni-plugin image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C apiserver image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C kube-controllers image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C app-policy image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C typha image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)
	$(MAKE) -C node image IMAGETAG=$(GIT_VERSION) VALIDARCHES=$(ARCH)

###############################################################################
# Run local e2e smoke test against the checked-out code
# using a local kind cluster.
###############################################################################
E2E_FOCUS ?= "sig-network.*Conformance"
ADMINPOLICY_SUPPORTED_FEATURES ?= "AdminNetworkPolicy,BaselineAdminNetworkPolicy"
ADMINPOLICY_UNSUPPORTED_FEATURES ?= ""
e2e-test:
	$(MAKE) -C e2e build
	$(MAKE) -C node kind-k8st-setup
	KUBECONFIG=$(KIND_KUBECONFIG) ./e2e/bin/k8s/e2e.test -ginkgo.focus=$(E2E_FOCUS)
	KUBECONFIG=$(KIND_KUBECONFIG) ./e2e/bin/adminpolicy/e2e.test \
	  -exempt-features=$(ADMINPOLICY_UNSUPPORTED_FEATURES) \
	  -supported-features=$(ADMINPOLICY_SUPPORTED_FEATURES)

e2e-test-adminpolicy:
	$(MAKE) -C e2e build
	$(MAKE) -C node kind-k8st-setup
	KUBECONFIG=$(KIND_KUBECONFIG) ./e2e/bin/adminpolicy/e2e.test \
	  -exempt-features=$(ADMINPOLICY_UNSUPPORTED_FEATURES) \
	  -supported-features=$(ADMINPOLICY_SUPPORTED_FEATURES)

###############################################################################
# Release logic below
###############################################################################
.PHONY: release release-publish create-release-branch release-test build-openstack publish-openstack release-notes
# Build the release tool.
release/bin/release: $(shell find ./release -type f -name '*.go')
	$(MAKE) -C release

# Install ghr for publishing to github.
bin/ghr:
	$(DOCKER_RUN) -e GOBIN=/go/src/$(PACKAGE_NAME)/bin/ $(CALICO_BUILD) go install github.com/tcnksm/ghr@$(GHR_VERSION)

# Build a release.
release: release/bin/release
	@release/bin/release release build

# Publish an already built release.
release-publish: release/bin/release bin/ghr
	@release/bin/release release publish

# Create a release branch.
create-release-branch: release/bin/release
	@release/bin/release branch cut -git-publish

# Test the release code
release-test:
	$(DOCKER_RUN) $(CALICO_BUILD) ginkgo -cover -r release/pkg

# Currently our openstack builds either build *or* build and publish,
# hence why we have two separate jobs here that do almost the same thing.
build-openstack: bin/yq
	$(eval VERSION=$(shell bin/yq '.version' charts/calico/values.yaml))
	$(info Building openstack packages for version $(VERSION))
	$(MAKE) -C release/packaging release VERSION=$(VERSION)

publish-openstack: bin/yq
	$(eval VERSION=$(shell bin/yq '.version' charts/calico/values.yaml))
	$(info Publishing openstack packages for version $(VERSION))
	$(MAKE) -C release/packaging release-publish VERSION=$(VERSION)

## Kicks semaphore job which syncs github released helm charts with helm index file
.PHONY: helm-index
helm-index:
	@echo "Triggering semaphore workflow to update helm index."
	SEMAPHORE_PROJECT_ID=30f84ab3-1ea9-4fb0-8459-e877491f3dea \
			     SEMAPHORE_WORKFLOW_BRANCH=master \
			     SEMAPHORE_WORKFLOW_FILE=../releases/calico/helmindex/update_helm.yml \
			     $(MAKE) semaphore-run-workflow

# Creates the tar file used for installing Calico on OpenShift.
bin/ocp.tgz: manifests/ocp/ bin/yq
	tar czvf $@ --exclude='.gitattributes' -C manifests/ ocp

## Generates release notes for the given version.
.PHONY: release-notes
release-notes:
	@$(MAKE) -C release release-notes

## Update the AUTHORS.md file.
update-authors:
ifndef GITHUB_TOKEN
	$(error GITHUB_TOKEN must be set)
endif
	@echo "# Calico authors" > AUTHORS.md
	@echo "" >> AUTHORS.md
	@echo "This file is auto-generated based on commit records reported" >> AUTHORS.md
	@echo "by git for the projectcalico/calico repository. It is ordered alphabetically." >> AUTHORS.md
	@echo "" >> AUTHORS.md
	@docker run -ti --rm --net=host \
		-v $(REPO_ROOT):/code \
		-w /code \
		-e GITHUB_TOKEN=$(GITHUB_TOKEN) \
		python:3 \
		bash -c '/usr/local/bin/python release/get-contributors.py >> /code/AUTHORS.md'

update-pins: update-go-build-pin update-calico-base-pin

###############################################################################
# Post-release validation
###############################################################################
POSTRELEASE_IMAGE=calico/postrelease
POSTRELEASE_IMAGE_CREATED=.calico.postrelease.created
$(POSTRELEASE_IMAGE_CREATED):
	cd hack/postrelease && docker build -t $(POSTRELEASE_IMAGE) .
	touch $@

postrelease-checks: $(POSTRELEASE_IMAGE_CREATED)
	$(DOCKER_RUN) \
		-v /var/run/docker.sock:/var/run/docker.sock \
		-e VERSION=$(VERSION) \
		-e FLANNEL_VERSION=$(FLANNEL_VERSION) \
		-e VPP_VERSION=$(VPP_VERSION) \
		-e OPERATOR_VERSION=$(OPERATOR_VERSION) \
		$(POSTRELEASE_IMAGE) \
		sh -c "nosetests hack/postrelease -e "$(EXCLUDE_REGEX)" -s -v --with-xunit --xunit-file='postrelease-checks.xml' --with-timer $(EXTRA_NOSE_ARGS)"
