# Debian source packages: one .dsc/.changes/.tar.xz set per (component, series).
#
# Each build runs against its own staging copy under output/src/, so the source
# tree is never modified, the three series never race over one
# debian/changelog, and `make -j` is safe.  Signing happens at publish time,
# hence the explicit -us -uc.

UBUNTU_COMPONENTS := $(strip $(foreach c,$(COMPONENTS),$(if $(filter ubuntu,$(PLATFORMS_$(c))),$(c))))

# dpkg leaves the epoch out of file names, so these carry $(DEB_VERSION)
# without DEB_EPOCH_<pkg>.  $(1) is the component, $(2) the series.
deb_changes_file  = $(OUTPUT_DIR)/$(1)_$(DEB_VERSION)-$(2)_source.changes
deb_changes_files = $(foreach s,$(UBUNTU_SERIES),$(call deb_changes_file,$(1),$(s)))

DEB_SOURCE_PACKAGES := $(foreach c,$(UBUNTU_COMPONENTS),$(call deb_changes_files,$(c)))

.PHONY: build-ubuntu
build-ubuntu: $(DEB_SOURCE_PACKAGES)

# One component, all series: `make build-ubuntu-felix`.
build-ubuntu-%:
	@test -n "$(filter $*,$(UBUNTU_COMPONENTS))" || \
	    { echo "[error] '$*' is not built for ubuntu (have: $(UBUNTU_COMPONENTS))"; exit 1; }
	$(MAKE) $(call deb_changes_files,$*)

# Everything the recipe below needs, read out of the target name.  The stem of
# the static pattern rule is '<pkg>_<debversion>-<series>'.
deb_pkg    = $(firstword $(subst _, ,$*))
deb_series = $(lastword $(filter $(UBUNTU_SERIES),$(subst -, ,$*)))
deb_stage  = $(call deb_stage_dir,$(deb_pkg),$(deb_series))
deb_msg    = $(if $(IS_RELEASE),$(NAME_$(deb_pkg)) v$(DEB_VERSION),Development snapshot) (from Git commit $(GIT_COMMIT)).

# No -I: dpkg-source ignores nothing unless asked to, and a bare `-I` *adds* its
# default ignore list, which drops files the packages ship - Felix's BPF *.o
# objects, for one.  The staging copy is already exactly what we want to package,
# so the excludes all happen there instead.  Per-package debian/source/options
# still applies.
DPKG_BUILDPACKAGE_ARGS := -S -d -us -uc

.SECONDEXPANSION:

$(DEB_SOURCE_PACKAGES): $(OUTPUT_DIR)/%_source.changes: $$(PREPARE_$$(deb_pkg)) \
                            | $(OUTPUT_DIR) $$(addprefix images-ubuntu-,$$(deb_series)) check-deb-build-tools
	$(UTILS)/stage-source $(DIR_$(deb_pkg)) $(deb_stage) '$(EXCLUDES_$(deb_pkg))'
	$(if $(STAGE_HOOK_$(deb_pkg)),$(STAGE_HOOK_$(deb_pkg)) $(deb_stage) $(PEP440_VERSION))
	$(if $(DEB_STAGE_HOOK_$(deb_pkg)),$(DEB_STAGE_HOOK_$(deb_pkg)) $(deb_stage) $(PEP440_VERSION))
	$(UTILS)/write-deb-changelog $(deb_stage) $(deb_pkg) \
	    '$(DEB_EPOCH_$(deb_pkg))$(DEB_VERSION)-$(deb_series)' $(deb_series) '$(deb_msg)'
	docker run --rm --user $(DOCKER_USER) \
	    -v $(SRC_DIR)/$(deb_series):/code -w /code/$(deb_pkg) \
	    calico-build/$(deb_series) dpkg-buildpackage $(DPKG_BUILDPACKAGE_ARGS)
	mv $(SRC_DIR)/$(deb_series)/$(deb_pkg)_$(DEB_VERSION)-$(deb_series)* $(OUTPUT_DIR)/
