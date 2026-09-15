# Build and publish the Calico .deb and .rpm packages.
#
# Usage is documented in README.md; the architecture, the invariants and the
# rationale are in DESIGN.md.  In short:
#
#   make build            # deb source packages + RPMs, under output/
#   make build-binaries   # local .deb files, built from the source packages
#   make test             # install what we built in clean containers
#   make publish          # upload to the PPA, the RPM repo and GAR
#
# Every target below `build`, `build-binaries` and `publish` resolves to a file
# under output/, so re-running is a no-op and a failed run resumes.

# Absolute path of this directory, so that `make -C release/packaging <target>`
# behaves exactly like running make from here.
PACKAGING_DIR := $(patsubst %/,%,$(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

include $(PACKAGING_DIR)/mk/config.mk
include $(PACKAGING_DIR)/mk/components.mk
include $(PACKAGING_DIR)/mk/images.mk
include $(PACKAGING_DIR)/mk/felix-el8.mk
include $(PACKAGING_DIR)/mk/build-ubuntu.mk
include $(PACKAGING_DIR)/mk/build-rhel.mk
include $(PACKAGING_DIR)/mk/binaries.mk
include $(PACKAGING_DIR)/mk/publish-ubuntu.mk
include $(PACKAGING_DIR)/mk/publish-rhel.mk
include $(PACKAGING_DIR)/mk/test.mk

.DEFAULT_GOAL := help

# --- aggregates -----------------------------------------------------------

.PHONY: build publish test images clean
build: build-ubuntu build-rhel
publish: publish-ubuntu publish-rhel
test: test-ubuntu test-rhel
images: images-ubuntu images-rhel

clean:
	rm -rf $(OUTPUT_DIR)

# --- directories ----------------------------------------------------------

$(OUTPUT_DIR) $(SRC_DIR) $(BINARIES_DIR) $(STAMP_DIR) $(LAUNCHPAD_DIR):
	mkdir -p $@

# --- compatibility aliases ------------------------------------------------
#
# The root Makefile's build-openstack/publish-openstack targets and
# .semaphore/push-images/packaging.yaml call these.  They clean first, so that
# they behave exactly as the shell script they replaced did; new-style
# invocations (`make build`, `make publish`) are incremental.  Each phase is a
# separate sub-make so that the makefiles are re-read after the clean.
.PHONY: release release-publish
release:
	$(MAKE) clean
	$(MAKE) build

release-publish:
	$(MAKE) clean
	$(MAKE) build
	$(MAKE) publish

# --- help -----------------------------------------------------------------

.PHONY: help
help:
	@echo "Calico packaging - build and publish .deb and .rpm packages."
	@echo
	@echo "Build:"
	@echo "  images                   Build the per-platform build containers."
	@echo "  build                    Everything below: deb source packages and RPMs."
	@echo "  build-ubuntu             Deb source packages (.dsc/.changes) for $(UBUNTU_SERIES)."
	@echo "  build-ubuntu-<pkg>       Just one component."
	@echo "  build-rhel               RPMs for EL $(EL_VERSIONS), into output/dist/."
	@echo "  build-rhel-<pkg>         Just one component."
	@echo "  build-binaries           Binary .debs from the source packages, for local use."
	@echo
	@echo "Test (optional, needs build-binaries / build-rhel output):"
	@echo "  test                     test-ubuntu and test-rhel."
	@echo "  test-ubuntu[-<series>]   Install the .debs in a stock ubuntu image and check them."
	@echo "  test-rhel                Install the RPMs in a stock centos image and check them."
	@echo
	@echo "Publish:"
	@echo "  publish                  publish-ubuntu and publish-rhel."
	@echo "  publish-ubuntu           dput each source package to the PPA."
	@echo "  publish-rhel             publish-rhel-bpo and publish-rhel-gar."
	@echo "  publish-rhel-bpo         RPM repo on binaries.projectcalico.org."
	@echo "  publish-rhel-gar         Google Artifact Registry yum repo."
	@echo
	@echo "Other:"
	@echo "  clean                    Remove output/."
	@echo "  print-config             Show the derived version and repo names."
	@echo
	@echo "Components: $(COMPONENTS)"
	@echo "Run 'make print-config' to see what VERSION=$(VERSION) resolves to."
