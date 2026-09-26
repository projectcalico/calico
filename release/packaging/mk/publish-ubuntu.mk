# Upload the Debian source packages to the PPA.
#
# One target per .changes file.  dput writes <base>.ppa.upload on success, so
# that file *is* the stamp: re-running skips completed uploads with no extra
# bookkeeping.  Launchpad then builds and signs the binary packages itself,
# which is why we never upload the .debs from build-binaries.

PPA                := ppa:$(PPA_OWNER)/$(REPO_NAME)
PPA_URL            := https://launchpad.net/~$(PPA_OWNER)/+archive/ubuntu/$(REPO_NAME)
PPA_CONTENT_URL    := https://ppa.launchpadcontent.net/$(PPA_OWNER)/$(REPO_NAME)/ubuntu
LAUNCHPAD_INDEXES  := $(addsuffix .sources,$(addprefix $(LAUNCHPAD_DIR)/,$(UBUNTU_SERIES)))
DEB_UPLOAD_STAMPS  := $(DEB_SOURCE_PACKAGES:.changes=.ppa.upload)

.PHONY: publish-ubuntu
publish-ubuntu: $(DEB_UPLOAD_STAMPS)

# The series is in the target name; the stem is '<pkg>_<debversion>-<series>_source'.
upload_series = $(lastword $(filter $(UBUNTU_SERIES),$(subst -, ,$(subst _, ,$*))))

.SECONDEXPANSION:

$(DEB_UPLOAD_STAMPS): $(OUTPUT_DIR)/%.ppa.upload: $(OUTPUT_DIR)/%.changes \
                          | $$(LAUNCHPAD_DIR)/$$(upload_series).sources check-ppa \
                            $$(addprefix images-ubuntu-,$$(upload_series))
	$(UTILS)/publish-deb-source $< $(PPA) $(LAUNCHPAD_DIR)/$(upload_series).sources

# What Launchpad already has, so that we can skip those uploads instead of
# having them rejected.  A PPA with no packages for a series yet has no index,
# which is not an error - it just means nothing to skip.
$(LAUNCHPAD_DIR)/%.sources: | $(LAUNCHPAD_DIR)
	@echo "Fetching the list of source packages the PPA already has for $* ..."
	@if curl -fsSL "$(PPA_CONTENT_URL)/dists/$*/main/source/Sources.gz" -o $@.gz; then \
	    zcat $@.gz > $@ && rm -f $@.gz; \
	else \
	    echo "  (no source index for $* yet)"; \
	    : > $@; \
	fi

# The one manual step in the whole pipeline.
.PHONY: check-ppa
check-ppa:
	@curl -fsSL -I "$(PPA_URL)" > /dev/null || { \
	    echo "[error] the PPA for '$(REPO_NAME)' does not exist.  Create it, then rerun:"; \
	    echo "  - go to https://launchpad.net/~$(PPA_OWNER) and note the name and"; \
	    echo "    description of the PPA for the previous Calico release series;"; \
	    echo "  - create a new PPA with a similar name and description for this one."; \
	    exit 1; \
	}
