PACKAGE_NAME = github.com/projectcalico/calico

include ../metadata.mk
include ../lib.Makefile

###############################################################################
# API validation tests (envtest-based, CEL XValidation rules)
###############################################################################
.PHONY: ut-validation
## Run CRD validation tests against the default K8s version.
ut-validation: setup-envtest
	$(DOCKER_RUN) \
		-v $$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1):/envtest:ro \
		-e KUBEBUILDER_ASSETS=/envtest \
		$(CALICO_BUILD) \
		go test -count=1 -v ./test/validation/...

.PHONY: ut-validation-min-k8s
## Run CRD validation tests against the minimum supported K8s version (1.29).
ut-validation-min-k8s: setup-envtest-min
	$(DOCKER_RUN) \
		-v $$(ls -d $(ENVTEST_DIR)/k8s/$(ENVTEST_MIN_K8S_MINOR)*-$(BUILDOS)-$(BUILDARCH) | tail -1):/envtest:ro \
		-e KUBEBUILDER_ASSETS=/envtest \
		$(CALICO_BUILD) \
		go test -count=1 -v ./test/validation/...

.PHONY: ci
## Run all test/ CI jobs.
ci: ut-validation ut-validation-min-k8s
