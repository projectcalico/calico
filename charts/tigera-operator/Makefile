include ../../metadata.mk
include ../../lib.Makefile

OPERATOR_REPO ?= tigera/operator
OPERATOR_VERSION ?= $(shell grep '^ *version:' values.yaml | sed -e 's/.*version: //')


fetch-manifests:
	$(eval tmp_dir := $(shell mktemp -d))
	git clone --depth=1 -b $(OPERATOR_VERSION) https://github.com/$(OPERATOR_REPO) $(tmp_dir)
	for kind in apiservers imagesets installations tigerastatuses; do \
		cp $(tmp_dir)/pkg/crds/operator/operator.tigera.io_$$kind.yaml crds/operator.tigera.io_$${kind}_crd.yaml; \
	done
	rm -rf $(tmp_dir)
