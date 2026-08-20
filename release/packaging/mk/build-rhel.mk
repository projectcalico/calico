# RPMs, one target per (component, EL version), all writing into
# output/dist/rpms-el<n>/.
#
# The container invocation and rpm/build-rpms are as they were; what changed is
# that the spec templating and the source tarball now come from a staging copy
# instead of the working tree.  RPM file names are derivable but tedious - epoch,
# %{dist}, sub-packages - so these targets are stamped rather than named after
# every RPM they produce.

RHEL_COMPONENTS := $(strip $(foreach c,$(COMPONENTS),$(if $(filter rhel,$(PLATFORMS_$(c))),$(c))))

# $(1) is the component, $(2) the EL version.
rpm_stamp  = $(STAMP_DIR)/rpm-$(1)-el$(2)
rpm_stamps = $(foreach e,$(EL_VERSIONS),$(call rpm_stamp,$(1),$(e)))

RPM_STAMPS := $(foreach c,$(RHEL_COMPONENTS),$(call rpm_stamps,$(c)))

.PHONY: build-rhel
build-rhel: $(RPM_STAMPS)

# One component, all EL versions: `make build-rhel-felix`.
build-rhel-%:
	@test -n "$(filter $*,$(RHEL_COMPONENTS))" || \
	    { echo "[error] '$*' is not built for rhel (have: $(RHEL_COMPONENTS))"; exit 1; }
	$(MAKE) $(call rpm_stamps,$*)

# Read out of the target name; the stem is '<pkg>-el<n>'.
rpm_el    = $(lastword $(subst -el, ,$*))
rpm_pkg   = $(patsubst %-el$(rpm_el),%,$*)
rpm_stage = $(call rpm_stage_dir,$(rpm_pkg))
rpm_msg   = $(if $(IS_RELEASE),$(NAME_$(rpm_pkg)) v$(PEP440_VERSION),Development snapshot) (from Git commit $(GIT_COMMIT)).

.SECONDEXPANSION:

# The repo root is mounted at /code because that is where build-rpms writes its
# output, under release/packaging/output/dist/; the working directory is the
# staging copy, whose basename build-rpms takes as the package name.
rpm_stage_in_container = /code/$(patsubst $(REPO_ROOT)/%,%,$(rpm_stage))

$(RPM_STAMPS): $(STAMP_DIR)/rpm-%: $$(PREPARE_$$(rpm_pkg)) \
                   | $(STAMP_DIR) $$(addprefix images-rhel-el,$$(rpm_el)) check-rpm-build-tools
	$(UTILS)/stage-source $(DIR_$(rpm_pkg)) $(rpm_stage) '$(EXCLUDES_$(rpm_pkg))'
	$(if $(STAGE_HOOK_$(rpm_pkg)),$(STAGE_HOOK_$(rpm_pkg)) $(rpm_stage) $(PEP440_VERSION))
	$(UTILS)/write-rpm-spec $(rpm_stage) $(RPM_VER) $(RPM_REL) '$(rpm_msg)'
	mkdir -p $(call rpm_output_dir,$(rpm_el))
	docker run --rm --user $(DOCKER_USER) \
	    -e EL_VERSION=el$(rpm_el) \
	    -v $(PACKAGING_DIR)/rpm:/rpm \
	    -v $(REPO_ROOT):/code \
	    -w $(rpm_stage_in_container) \
	    calico-build/el$(rpm_el) /rpm/build-rpms
	touch $@
