# Binary .debs, built locally from the source packages we just made.
#
# These are not published: Launchpad builds the official ones, in the PPA's own
# environment and signed by Launchpad.  Ours exist so that a source package that
# does not build is caught here, in minutes, instead of an hour later in a PPA
# build log - and so that `test` has something to install.
#
# The calico-build/<series> images already carry the Build-Depends, which is
# what install-ubuntu-build-deps is for.

BINARY_DEB_STAMPS := $(addprefix $(STAMP_DIR)/binaries-,$(UBUNTU_SERIES))

.PHONY: build-binaries
build-binaries: $(BINARY_DEB_STAMPS)

.PHONY: $(addprefix build-binaries-,$(UBUNTU_SERIES))
$(addprefix build-binaries-,$(UBUNTU_SERIES)): build-binaries-%: $(STAMP_DIR)/binaries-%

# Per series, one stamp depending on that series' source packages.  The .dsc
# files are unpacked and built inside the build image, and the .deb files land in
# output/binaries/<series>/.
.SECONDEXPANSION:

$(BINARY_DEB_STAMPS): $(STAMP_DIR)/binaries-%: \
                          $$(foreach c,$$(UBUNTU_COMPONENTS),$$(call deb_changes_file,$$(c),$$*)) \
                          | $(STAMP_DIR) $$(addprefix images-ubuntu-,$$*) check-deb-build-tools
	docker run --rm --user $(DOCKER_USER) \
	    -v $(OUTPUT_DIR):/output -v $(UTILS):/utils:ro -w /output \
	    calico-build/$* /utils/build-binary-debs $*
	touch $@
