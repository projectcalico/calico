include ../metadata.mk

PACKAGE_NAME = github.com/projectcalico/calico/webhooks

###############################################################################
# include ../lib.Makefile
#   Additions to EXTRA_DOCKER_ARGS need to happen before the include since
#   that variable is evaluated when we declare DOCKER_RUN and siblings.
###############################################################################
include ../lib.Makefile

clean:
	rm -rf bin

###############################################################################
# UTs
###############################################################################
ci: static-checks ut ut-authz
## ./pkg/... rather than ./... so that ut does not pick up ./test/authz, which needs the envtest
## binaries. Anything new outside ./pkg needs adding here.
ut:
	mkdir -p report
	$(DOCKER_GO_BUILD) gotestsum --junitfile report/webhooks_ut.xml -- ./pkg/... -coverprofile coverage.profile -race -count 1

## Run the authorization webhook suite against a real kube-apiserver.
.PHONY: ut-authz
ut-authz: setup-envtest
	mkdir -p report
	$(DOCKER_RUN) \
		-v $$(ls -d $(ENVTEST_DIR)/k8s/*-$(BUILDOS)-$(BUILDARCH) | tail -1):/envtest:ro \
		-e KUBEBUILDER_ASSETS=/envtest \
		$(CALICO_BUILD) \
		gotestsum --junitfile report/ut-authz.xml -- -count=1 -v ./test/authz/...

gen-mocks:
	$(DOCKER_RUN) $(CALICO_BUILD) sh -c 'mockery'
