#!/bin/bash

# rpms-image-lib.sh: Names for the images that hack/rpms/<package> builds.
# Sourced by the build, load and push scripts for those images.

# The arches each image is built for, and that its multi-arch manifest lists.
RPMS_ARCHES="amd64 arm64 ppc64le s390x"

# rpms_image_vars <package> sets:
#   RPMS_REPO   the image repository, without a tag
#   RPMS_CACHE  the prefix of the image's tarball in the workflow cache
#   RPMS_TAG    the content-addressed tag, without an arch suffix
rpms_image_vars() {
  local package=$1 repo_root
  case "$package" in
    bird)
      RPMS_REPO=calico/bird
      RPMS_CACHE=bird-image
      ;;
    nftables)
      RPMS_REPO=calico/nftables-rpms
      RPMS_CACHE=nft-rpms
      ;;
    *)
      echo "Unknown package '${package}': expected bird or nftables" >&2
      return 1
      ;;
  esac
  repo_root=$(git rev-parse --show-toplevel)
  RPMS_TAG=$(make --no-print-directory -C "${repo_root}/hack/rpms/${package}" print-tag)
}
