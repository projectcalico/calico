include ../../metadata.mk
include ../../lib.Makefile

OPERATOR_REPO ?= tigera/operator
OPERATOR_VERSION ?= master

TMP_DIR = .tmp

CHECKOUT_DIR = $(TMP_DIR)/operator

clean:
	rm -rf $(CHECKOUT_DIR)

$(CHECKOUT_DIR):
	mkdir -p $(CHECKOUT_DIR)
	git clone --depth=1 -b $(OPERATOR_VERSION) https://github.com/$(OPERATOR_REPO) $(CHECKOUT_DIR)

fetch-manifests: $(CHECKOUT_DIR)
	for kind in apiservers imagesets installations tigerastatuses; do \
		echo "Kind: $$kind"; \
		echo "$(CHECKOUT_DIR)/pkg/crds/operator/operator.tigera.io_$$kind.yaml crds/operator.tigera.io_$${kind}_crd.yaml"; \
	done
	$(MAKE) clean
