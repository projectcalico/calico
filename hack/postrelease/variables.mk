# NOSE_PROCESSES: how many concurrent test processes to run
NOSE_PROCESSES := 0

# Manifests and charts files (for getting versions from)
CHARTS_TIGERAOPERATOR_VALUES = ../../charts/tigera-operator/values.yaml
CHART_CALICO_VALUES  = ../../charts/calico/values.yaml

# Versions (extracted from the manifests files)
CALICO_VERSION  := $(shell yq '.calicoctl.tag'  < $(CHARTS_TIGERAOPERATOR_VALUES))
OPERATOR_VERSION := $(shell yq '.tigeraOperator.version' < $(CHARTS_TIGERAOPERATOR_VALUES))
FLANNEL_VERSION := $(shell yq '.flannel.tag' < $(CHART_CALICO_VALUES))

# The docker image that we build to run the tests in
CALICO_POSTRELEASE_TEST_IMAGE = calico_postrelease_tests:$(CALICO_VERSION)
