# Install verification.
#
# Not part of `build` or `publish`: run it explicitly, or wire it into CI as a
# gate between the two.  The containers here are *stock* ubuntu and centos
# images, not the build images - a build image has the dev packages installed
# and would hide a missing runtime dependency, which is exactly the class of bug
# this is here to catch.

UBUNTU_TEST_TARGETS := $(addprefix test-ubuntu-,$(UBUNTU_SERIES))
RHEL_TEST_TARGETS   := $(addprefix test-rhel-el,$(EL_VERSIONS))

.PHONY: test-ubuntu test-rhel $(UBUNTU_TEST_TARGETS) $(RHEL_TEST_TARGETS)

test-ubuntu: $(UBUNTU_TEST_TARGETS)
test-rhel: $(RHEL_TEST_TARGETS)

# The commands below run inside the container, so '$$' is a literal '$' for its
# shell, while '$*' is the series or EL version from the target name.  Both
# install what we built, then hand the installed package names to
# check-installed-package.
TEST_UBUNTU_CMD = set -eu; \
	export DEBIAN_FRONTEND=noninteractive; \
	apt-get -q update; \
	apt-get install -y -q /output/binaries/$*/*.deb; \
	packages=$$(for d in /output/binaries/$*/*.deb; do dpkg-deb -f "$$d" Package; done); \
	/utils/check-installed-package $$packages

$(UBUNTU_TEST_TARGETS): test-ubuntu-%: $(STAMP_DIR)/binaries-%
	docker run --rm \
	    -v $(OUTPUT_DIR):/output:ro -v $(UTILS):/utils:ro \
	    ubuntu:$* bash -c '$(TEST_UBUNTU_CMD)'

# RPM_TEST_PACKAGES selects what to install: some of our RPMs need OpenStack
# repositories that a stock centos image does not have.
# Only double quotes in here: the whole thing is passed to bash -c inside single
# quotes.
TEST_RHEL_CMD = set -eu; \
	rpms=; packages=; \
	for r in $$(find /output/dist/rpms-el$* -name "*.rpm" -not -name "*.src.rpm" | sort); do \
	    n=$$(rpm -qp --queryformat "%{NAME}" "$$r"); \
	    case " $(RPM_TEST_PACKAGES) " in \
	        *" $$n "*) rpms="$$rpms $$r"; packages="$$packages $$n";; \
	    esac; \
	done; \
	test -n "$$rpms" || { echo "[error] none of these were built: $(RPM_TEST_PACKAGES)"; exit 1; }; \
	dnf install -y $$rpms; \
	/utils/check-installed-package $$packages

# A stock almalinux image, not the build image: the build image has the -devel
# packages installed and would hide a missing runtime dependency.
$(RHEL_TEST_TARGETS): test-rhel-el%: $$(foreach c,$$(RHEL_COMPONENTS),$$(call rpm_stamp,$$(c),$$*))
	docker run --rm \
	    -v $(OUTPUT_DIR):/output:ro -v $(UTILS):/utils:ro \
	    almalinux:$* bash -c '$(TEST_RHEL_CMD)'
