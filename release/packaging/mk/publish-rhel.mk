# Publish the RPMs, to two independent places:
#
#   publish-rhel-bpo  the RPM repo on binaries.projectcalico.org
#   publish-rhel-gar  the Google Artifact Registry yum repo
#
# They are siblings: either order, or in parallel, and `publish-rhel` fails if
# either fails.  Both are skip-if-already-present per artifact, so a failed run
# can simply be repeated.

SSH_HOST := gcloud --quiet compute ssh $(GCLOUD_ARGS) $(HOST)
SCP_HOST := gcloud --quiet compute scp $(GCLOUD_ARGS)

RPM_DIST_DIRS := $(foreach e,$(EL_VERSIONS),$(call rpm_output_dir,$(e)))

# publish-rpm-to-gar reads these.
export GAR_LOCATION
export GCLOUD_PROJECT

.PHONY: publish-rhel publish-rhel-bpo publish-rhel-gar
publish-rhel: publish-rhel-bpo publish-rhel-gar

# Repository metadata is rebuilt after the copy: old RPMs pruned, everything
# re-signed with the Project Calico Maintainers key, the public key published
# beside it, and the repo index regenerated.
publish-rhel-bpo: | check-rpms-exist check-publish-rhel-tools
	$(SSH_HOST) -- mkdir -p $(RPM_REMOTE_DIR)/$(REPO_NAME)
	for arch in src noarch x86_64; do \
	    files=$$(find $(RPM_DIST_DIRS) -name "*.$$arch.rpm" | sort) || true; \
	    test -n "$$files" || continue; \
	    $(SSH_HOST) -- mkdir -p $(RPM_REMOTE_DIR)/$(REPO_NAME)/$$arch/; \
	    $(SCP_HOST) $$files $(HOST):$(RPM_REMOTE_DIR)/$(REPO_NAME)/$$arch/; \
	done
	$(UTILS)/refresh-rpm-repo $(REPO_NAME) $(RPM_REMOTE_DIR) '$(RPM_SIGNING_KEY_NAME)' | $(SSH_HOST)

# Source RPMs are deliberately not uploaded to GAR.
publish-rhel-gar: | check-rpms-exist check-publish-rhel-tools
	@echo "Uploading RPMs to Google Artifact Registry repository $(GCLOUD_REPO_NAME)"
	for rpm in $$(find $(RPM_DIST_DIRS) -name '*.rpm' -not -name '*.src.rpm' | sort); do \
	    $(UTILS)/publish-rpm-to-gar "$$rpm" $(GCLOUD_REPO_NAME); \
	done

.PHONY: check-rpms-exist
check-rpms-exist:
	@test -n "$$(find $(RPM_DIST_DIRS) -name '*.rpm' 2>/dev/null)" || { \
	    echo "[error] no RPMs under $(RPM_DIST_DIRS) - run 'make build-rhel' first"; \
	    exit 1; \
	}
