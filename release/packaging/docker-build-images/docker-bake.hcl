# docker-bake.hcl

# To use a different arch, define it in an environment variable;
# for example, `ARCH=ppc64le docker buildx bake`.
variable "ARCH" {
    default = "amd64"
}

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
    targets = ["centos"]
}

# All centos images
group "centos" {
    targets = ["centos8"]
}

# All Ubuntu builds - in one big matrix, using one Dockerfile
target "ubuntu" {
  name = "ubuntu-${STREAM}-${ARCH}"
  dockerfile = "ubuntu.Dockerfile"
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

# CentOS builds
target "centos8" {
  dockerfile = "centos8-build.Dockerfile.${ARCH}"
  args = {
    UID = UID
    GID = GID
  }
  tags = ["calico-build/centos8"]
}
