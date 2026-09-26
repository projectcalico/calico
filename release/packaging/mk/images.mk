# The containers we build packages in: calico-build/<series> and
# calico-build/centos<el>.
#
# These are always-run targets rather than files, because the state they produce
# lives in the docker image store, not in output/.  buildx's cache makes a
# no-change run cheap.  Everything that needs an image takes it as an
# order-only prerequisite, so a rebuilt image never invalidates a package that
# has already been built.

# docker-bake.hcl sits here, at the root of the build context it uses.
BAKE_DIR := $(PACKAGING_DIR)
BAKE     := docker buildx bake

UBUNTU_IMAGE_TARGETS := $(addprefix images-ubuntu-,$(UBUNTU_SERIES))
RHEL_IMAGE_TARGETS   := $(addprefix images-rhel-el,$(EL_VERSIONS))

.PHONY: images-ubuntu images-rhel $(UBUNTU_IMAGE_TARGETS) $(RHEL_IMAGE_TARGETS)

images-ubuntu: $(UBUNTU_IMAGE_TARGETS)
images-rhel: $(RHEL_IMAGE_TARGETS)

# These are static pattern rules rather than plain pattern rules because make
# does not search implicit rules for phony targets.
#
# UBUNTU_REPO_OVERRIDE is read from the environment by docker-bake.hcl, and
# points apt at a mirror; CI sets it.
$(UBUNTU_IMAGE_TARGETS): images-ubuntu-%:
	cd $(BAKE_DIR) && $(BAKE) ubuntu-$*-$(ARCH)

# rpmbuild needs the invoking user to exist inside the container, so the uid and
# gid are baked in.  GO_VERSION comes from the repo's metadata.mk: this image
# also builds calico-felix, against EL 8's glibc rather than go-build's.
$(RHEL_IMAGE_TARGETS): images-rhel-el%:
	cd $(BAKE_DIR) && GO_VERSION=$(GO_VERSION) $(BAKE) el$* \
	    --set el$*.args.UID=$(shell id -u) \
	    --set el$*.args.GID=$(shell id -g)
