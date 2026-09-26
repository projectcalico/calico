# Tunables, defaults, and version/repo-name derivation.
#
# Everything a caller might want to change is `?=`, so the environment and the
# command line still win and every existing CI invocation keeps working.
# See DESIGN.md section 6.

SHELL := /bin/bash
.SHELLFLAGS := -e -o pipefail -c

# --- layout ---------------------------------------------------------------

REPO_ROOT     := $(abspath $(PACKAGING_DIR)/../..)
UTILS         := $(PACKAGING_DIR)/utils
OUTPUT_DIR    := $(PACKAGING_DIR)/output
SRC_DIR       := $(OUTPUT_DIR)/src
BINARIES_DIR  := $(OUTPUT_DIR)/binaries
STAMP_DIR     := $(OUTPUT_DIR)/.stamps
LAUNCHPAD_DIR := $(OUTPUT_DIR)/.launchpad

# rpm/build-rpms writes here from inside the container, and
# .semaphore/release/release.yml archives the tree, so this path is fixed.
rpm_output_dir = $(OUTPUT_DIR)/dist/rpms-el$(1)

# --- publishing endpoints -------------------------------------------------

GCLOUD_ZONE          ?= us-east1-c
GCLOUD_PROJECT       ?= tigera-wp-tcp-redirect
GCLOUD_ARGS          ?= --zone $(GCLOUD_ZONE) --project $(GCLOUD_PROJECT)
HOST                 ?= ubuntu@binaries-projectcalico-org
GAR_LOCATION         ?= us-west1
RPM_REMOTE_DIR       ?= /usr/share/nginx/html/rpm
PPA_OWNER            ?= project-calico
# The key that RPMs on binaries.projectcalico.org are signed with, by uid.  It
# lives in the RPM host's keyring, not here.
RPM_SIGNING_KEY_NAME ?= Project Calico Maintainers

# --- signing (Launchpad source uploads) -----------------------------------
#
# SECRET_KEY_ID is preferred: the key is taken from the invoking user's GnuPG
# keyring at use time.  SECRET_KEY is the legacy path - a standalone key file -
# and wins when both are set, so CI needs no migration.  Neither is needed by
# anything except `publish-ubuntu`.
SECRET_KEY                 ?=
SECRET_KEY_ID              ?=
SECRET_KEY_PASSPHRASE_FILE ?=

# --- what to build --------------------------------------------------------

VERSION         ?= master
UBUNTU_SERIES   ?= focal jammy noble
# EL 8 is the oldest EL we package for.  It is also where calico-felix is built,
# because its glibc (2.28) is the oldest of every platform we ship to.
EL_VERSIONS     ?= 8
ARCH            ?= amd64

# The Go release used to build calico-felix for packaging, taken from the repo's
# own pin so that it cannot drift from what the containerised builds use.
GO_VERSION      ?= $(shell sed -n 's/^GO_VERSION=//p' $(REPO_ROOT)/metadata.mk)

# Which RPMs `test-rhel` installs.  Not every RPM we build is installable in a
# stock EL image - calico-compute and calico-control need OpenStack repos - so
# the install check covers the packages that ship ELF objects.
RPM_TEST_PACKAGES ?= calico-common calico-felix calicoctl

# --- docker ---------------------------------------------------------------

# Builds run as the invoking user so that everything under output/ stays
# writable and removable without sudo.
DOCKER_USER ?= $(shell id -u):$(shell id -g)

# --- REPO_NAME and GCLOUD_REPO_NAME ---------------------------------------
#
# Derived here and nowhere else (DESIGN.md invariant 7).  Google Artifact
# Registry forbids periods in repository names, so the GAR name drops them;
# the PPA and the binaries.projectcalico.org repo use REPO_NAME verbatim.

# vX.Y.Z
VERSION_PARTS := $(subst ., ,$(patsubst v%,%,$(VERSION)))
V_MAJOR       := $(word 1,$(VERSION_PARTS))
V_MINOR       := $(word 2,$(VERSION_PARTS))

# The two shapes that need a digits check, which Make cannot express.
VERSION_IS_SEMVER := $(shell [[ '$(VERSION)' =~ ^v[0-9]+\.[0-9]+\.[0-9]+$$ ]] && echo yes)
VERSION_IS_PR     := $(shell [[ '$(VERSION)' =~ ^pr-[0-9]+$$ ]] && echo yes)

ifeq ($(VERSION),master)
  DERIVED_REPO_NAME := master
  DERIVED_GAR_NAME  := master
else ifneq ($(filter release-v%,$(VERSION)),)
  DERIVED_REPO_NAME := testing
  DERIVED_GAR_NAME  := testing
else ifeq ($(VERSION_IS_PR),yes)
  DERIVED_REPO_NAME := $(VERSION)
  DERIVED_GAR_NAME  := $(VERSION)
else ifeq ($(VERSION_IS_SEMVER),yes)
  DERIVED_REPO_NAME := calico-$(V_MAJOR).$(V_MINOR)
  DERIVED_GAR_NAME  := calico-$(V_MAJOR)$(V_MINOR)
endif

REPO_NAME        ?= $(DERIVED_REPO_NAME)
GCLOUD_REPO_NAME ?= $(DERIVED_GAR_NAME)

ifeq ($(strip $(REPO_NAME)),)
  $(error Unhandled VERSION "$(VERSION)": expected master, release-vX.Y, pr-N or vX.Y.Z (or set REPO_NAME and GCLOUD_REPO_NAME explicitly))
endif
ifeq ($(strip $(GCLOUD_REPO_NAME)),)
  GCLOUD_REPO_NAME := $(REPO_NAME)
endif

# --- version derivation ---------------------------------------------------
#
# These goals do not name a package version, so we do not ask git for one -
# `make clean` must work in a shallow clone.
VERSIONLESS_GOALS := clean help images images-ubuntu images-rhel
ifneq ($(filter-out $(VERSIONLESS_GOALS),$(MAKECMDGOALS)),)
  NEED_VERSION := true
endif

# FORCE_VERSION skips the git lookup entirely; DEB_VERSION and RPM_VERSION can
# each be overridden on their own.
FORCE_VERSION ?=

ifdef NEED_VERSION
  GIT_VERSION := $(if $(FORCE_VERSION),$(FORCE_VERSION),$(shell cd $(REPO_ROOT) && VERSION='$(VERSION)' $(UTILS)/git-auto-version))
  PEP440_VERSION := $(patsubst v%,%,$(GIT_VERSION))
  ifeq ($(strip $(PEP440_VERSION)),)
    $(error Could not work out a package version from git state - is this a clone with tags? (git fetch --unshallow))
  endif
  GIT_COMMIT := $(shell cd $(REPO_ROOT) && git rev-parse --short=7 HEAD)

  # Our mainline development tags look like 'v3.31.0-0.dev', which
  # git-auto-version reports as '3.31.0rc0.post267'.  Debian needs a tilde -
  # '3.31.0~rc0.post267' - because it sorts logically *before* '3.31.0'.
  DEB_VERSION ?= $(subst rc,~rc,$(PEP440_VERSION))

  # RPM has no tilde, and no '-' is allowed in Version:, so a pre-release
  # qualifier is separated with '_' and then moved into Release: below.
  RPM_VERSION ?= $(subst -0.dev,_0.dev,$(PEP440_VERSION))
  RPM_VER  := $(lastword $(subst :, ,$(word 1,$(subst _, ,$(RPM_VERSION)))))
  RPM_QUAL := $(word 2,$(subst _, ,$(RPM_VERSION)))
  RPM_REL  := $(if $(RPM_QUAL),0.1.$(RPM_QUAL),1)

  # A version with no commits since the last tag is a release; anything else is
  # a development snapshot.
  IS_RELEASE := $(if $(findstring .post,$(PEP440_VERSION)),,true)
endif

# --- host tool checks -----------------------------------------------------
#
# Used as order-only prerequisites, so they never make a target look out of
# date.

.PHONY: check-deb-build-tools check-rpm-build-tools check-publish-rhel-tools

check-deb-build-tools:
	@for c in docker rsync dch patchelf; do \
	    command -v $$c >/dev/null || { \
	        echo "[error] '$$c' not found (dch is in devscripts, patchelf in patchelf)"; \
	        exit 1; \
	    }; \
	done

check-rpm-build-tools:
	@for c in docker rsync; do \
	    command -v $$c >/dev/null || { echo "[error] '$$c' not found"; exit 1; }; \
	done

check-publish-rhel-tools:
	@for c in gcloud jq rpm; do \
	    command -v $$c >/dev/null || { echo "[error] '$$c' not found"; exit 1; }; \
	done

# --- introspection --------------------------------------------------------

.PHONY: print-config
print-config:
	@echo "VERSION           = $(VERSION)"
	@echo "REPO_NAME         = $(REPO_NAME)"
	@echo "GCLOUD_REPO_NAME  = $(GCLOUD_REPO_NAME)"
	@echo "PEP440_VERSION    = $(PEP440_VERSION)"
	@echo "DEB_VERSION       = $(DEB_VERSION)"
	@echo "RPM_VERSION       = $(RPM_VERSION) (Version: $(RPM_VER), Release: $(RPM_REL))"
	@echo "GIT_COMMIT        = $(GIT_COMMIT)"
	@echo "IS_RELEASE        = $(if $(IS_RELEASE),yes,no)"
	@echo "UBUNTU_SERIES     = $(UBUNTU_SERIES)"
	@echo "EL_VERSIONS       = $(EL_VERSIONS)"
	@echo "COMPONENTS        = $(COMPONENTS)"
	@echo "  for ubuntu      = $(UBUNTU_COMPONENTS)"
	@echo "  for rhel        = $(RHEL_COMPONENTS)"
