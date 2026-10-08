# docker-bake.hcl
#
# This lives in release/packaging, not in docker-build-images, because the build
# context is the whole packaging directory.  See .dockerignore for what that
# context leaves out.

# To use a different arch, define it in an environment variable;
# for example, `ARCH=ppc64le docker buildx bake`.
variable "ARCH" {
    default = "amd64"
}

# The Go release the el8 image installs, so that it can build calico-felix
# against EL 8's glibc.  Set by mk/images.mk from the repo's GO_VERSION; no
# default, so an unset value fails the build rather than silently pinning a
# stale toolchain.
variable "GO_VERSION" {}

# The default Ubuntu stream
variable "STREAM" {
    default = "noble"
}

variable "UID" {
    default = 1000
}

variable "GID" {
    default = 1000
}

variable "UBUNTU_REPO_OVERRIDE" {
    default = ""
}

# Define groups for the builds we want to be able to do

# This is the default rule if you don't specify one. It'll build
# everything.

group "default" {
    targets = ["ubuntu", "rhel"]
}

# All EL images
group "rhel" {
    targets = ["el8"]
}

# All Ubuntu builds - in one big matrix, using one Dockerfile
target "ubuntu" {
  name = "ubuntu-${STREAM}-${ARCH}"
  dockerfile = "docker-build-images/ubuntu.Dockerfile"
  matrix = {
    STREAM = ["focal", "jammy", "noble"]
    ARCH = ["amd64"]
  }
  args = {
    STREAM = STREAM
    ARCH = ARCH
    UBUNTU_REPO_OVERRIDE = UBUNTU_REPO_OVERRIDE
  }
  tags = ["calico-build/${STREAM}"]
}

# EL builds.  This image both builds the RPMs and builds the calico-felix binary
# that every package ships - see docker-build-images/el8-build.Dockerfile.
target "el8" {
  dockerfile = "docker-build-images/el8-build.Dockerfile"
  args = {
    ARCH = ARCH
    GO_VERSION = "${GO_VERSION}"
    UID = UID
    GID = GID
  }
  tags = ["calico-build/el8"]
}
