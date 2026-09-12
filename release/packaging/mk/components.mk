# The component table: everything we know about what we package, as data.
#
# Adding a component is a stanza plus an entry in COMPONENTS.  No new rules.
# See DESIGN.md section 4.  Fields, all suffixed with the component name:
#
#   DIR_             where the component's source lives
#   NAME_            human-readable name, used in changelog entries
#   DEB_EPOCH_       Debian epoch prefix, for components that have needed one
#   PLATFORMS_       any of `ubuntu` and `rhel`
#   PREPARE_         target that must run before staging (builds shipped binaries)
#   EXCLUDES_        paths that must not reach the package source; one list for
#                    both formats, as rsync --exclude patterns
#   STAGE_HOOK_      command run on every staging copy; the Makefile appends
#                    <stagedir> <version>, so the field may carry leading
#                    arguments of its own
#   DEB_STAGE_HOOK_  the same, but only for the Debian staging copies

COMPONENTS := networking-calico felix calicoctl

DIR_networking-calico        := $(REPO_ROOT)/networking-calico
NAME_networking-calico       := networking-calico
DEB_EPOCH_networking-calico  := 3:
PLATFORMS_networking-calico  := ubuntu rhel
STAGE_HOOK_networking-calico := $(UTILS)/set-python-version
# The only file here that dpkg-source's default ignore list - which this package
# used to get, and no longer does - would have dropped.
EXCLUDES_networking-calico   := .gitignore

DIR_felix            := $(REPO_ROOT)/felix
NAME_felix           := Felix
DEB_EPOCH_felix      := 3:
PLATFORMS_felix      := ubuntu rhel
PREPARE_felix        := $(STAMP_DIR)/prepare-felix
DEB_STAGE_HOOK_felix := $(UTILS)/patch-felix-libpcap
# The binary we package is not felix/bin/calico-felix: it has to be built against
# an older glibc than calico/go-build has, so mk/felix-el8.mk builds its own and
# this installs it.  Deferred assignment, because that file is included after
# this one.
STAGE_HOOK_felix      = $(UTILS)/install-staged-file $(FELIX_EL8_BINARY) bin/calico-felix
# bin/calico-felix is excluded so that only the binary installed by the hook can
# ever reach a package.  bpf-gpl/bin/test_* are unit-test objects sitting
# alongside the BPF programs we ship, and both debian/rules and the spec install
# bpf-gpl/bin/*.
EXCLUDES_felix       := bin/calico-felix bin/calico-felix-* bpf-gpl/bin/test_* \
                        .git .gitignore *.d *.ll .go-pkg-cache vendor report

DIR_calicoctl       := $(REPO_ROOT)/calicoctl
NAME_calicoctl      := calicoctl
PLATFORMS_calicoctl := ubuntu rhel
PREPARE_calicoctl   := $(STAMP_DIR)/prepare-calicoctl
EXCLUDES_calicoctl  := bin/calicoctl-* .git .gitignore .go-pkg-cache \
                       report test-data tests

# Two components used to live here and no longer do, both for the same reason -
# they existed only for CentOS/RHEL 7:
#
#   dnsmasq   we built 2.79 ourselves because CentOS 7 was stuck on 2.76 and our
#             upstream patches need 2.79.  EL 8 ships 2.79.  Our fork, if it is
#             ever needed again, is github.com/projectcalico/calico-dnsmasq,
#             branch rpm_2.79.
#   etcd3gw   its spec built Python 2 packages, which EL 8 cannot.  As on Ubuntu,
#             which never had etcd3gw packaging, the answer is now
#             `pip install etcd3gw`.

# --- derived from the table ------------------------------------------------

# Staging directories: one per (component, platform) build, so that no two
# builds ever share a tree.  $(1) is the component, $(2) the Ubuntu series.
#
# The component name is the last element, because both dpkg-source and
# rpm/build-rpms name things after the directory they build in.
deb_stage_dir = $(SRC_DIR)/$(2)/$(1)
rpm_stage_dir = $(SRC_DIR)/rpm/$(1)

# --- prepare targets -------------------------------------------------------
#
# These build the binaries that the packages ship, because it is infeasible to
# work out a set of Debian and RPM golang build dependencies exactly equivalent
# to our containerised builds.  They write into the component's own bin/
# directory - its normal build output - and are stamped under output/, so that
# `make clean` forces a rebuild while a repeat `make build` does not, and so
# that several series building in parallel share one prepare.
#
# prepare-felix is in mk/felix-el8.mk, with the rest of the reason felix needs
# more than a plain `make bin/calico-felix`.

$(STAMP_DIR)/prepare-calicoctl: | $(STAMP_DIR)
	$(MAKE) -C $(DIR_calicoctl) bin/calicoctl
	touch $@
