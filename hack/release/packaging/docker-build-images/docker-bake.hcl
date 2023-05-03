# docker-bake.hcl

# To use a different arch, define it in an environment variable;
# for example, `ARCH=ppc64le docker buildx bake`. 
variable "ARCH" {
    default = "amd64"
}

variable "UID" {
    default = 1000
}

variable "GID" {
    default = 1000
}

# Define groups for the builds we want to be able to do

# This is the default rule if you don't specify one. It'll build
# everything.

group "default" {
    targets = ["ubuntu", "centos"]
}

# All ubuntu images
group "ubuntu" {
  targets = ["trusty", "xenial", "bionic", "focal", "jammy"]
}

# All centos images
group "centos" {
    targets = ["centos7"]
}

# Ubuntu builds
target "trusty" {
  dockerfile = "ubuntu-trusty-build.Dockerfile.${ARCH}"
  tags = ["calico-build/trusty"]
}
target "xenial" {
  dockerfile = "ubuntu-xenial-build.Dockerfile.${ARCH}"
  tags = ["calico-build/xenial"]
}
target "bionic" {
  dockerfile = "ubuntu-bionic-build.Dockerfile.${ARCH}"
  tags = ["calico-build/bionic"]
}
target "focal" {
  dockerfile = "ubuntu-focal-build.Dockerfile.${ARCH}"
  tags = ["calico-build/focal"]
}
target "jammy" {
  dockerfile = "ubuntu-jammy-build.Dockerfile.${ARCH}"
  tags = ["calico-build/jammy"]
}

# CentOS builds
target "centos7" {
  dockerfile = "centos7-build.Dockerfile.${ARCH}"
  args = {
    UID = UID
    GID = GID
  }
  tags = ["calico-build/centos7"]
}
