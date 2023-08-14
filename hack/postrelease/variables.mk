# Paths to override
YQ ?= yq

# Override implicit RM command quietly
RM := @$(RM)

# Manifests and charts files (for getting versions from)
CHARTS_TIGERAOPERATOR_VALUES = ../../charts/tigera-operator/values.yaml
CHART_CALICO_VALUES  = ../../charts/calico/values.yaml

# Versions (extracted from the charts files)
CALICO_VERSION  := $(shell yq '.calicoctl.tag'  < $(CHARTS_TIGERAOPERATOR_VALUES))
OPERATOR_VERSION := $(shell yq '.tigeraOperator.version' < $(CHARTS_TIGERAOPERATOR_VALUES))
FLANNEL_VERSION := $(shell yq '.flannel.tag' < $(CHART_CALICO_VALUES))

# The docker image that we build to run the tests in
CALICO_POSTRELEASE_TEST_IMAGE = calico_postrelease_tests:$(CALICO_VERSION)

.PHONY: show-variables

show-variables:
	$(info # Chart locations)
	$(info CHARTS_TIGERAOPERATOR_VALUES = $(CHARTS_TIGERAOPERATOR_VALUES))
	$(info CHART_CALICO_VALUES          = $(CHART_CALICO_VALUES))
	$(info )
	$(info # Versions (extracted from the manifests files))
	$(info CALICO_VERSION   = $(CALICO_VERSION))
	$(info OPERATOR_VERSION = $(OPERATOR_VERSION))
	$(info FLANNEL_VERSION  = $(FLANNEL_VERSION))
	$(info )
	$(info # The docker image that we build to run the tests in)
	$(info CALICO_POSTRELEASE_TEST_IMAGE = $(CALICO_POSTRELEASE_TEST_IMAGE))
