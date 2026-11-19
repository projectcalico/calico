#!/bin/bash

# rpms-image-lib.sh: Names for the images that hack/rpms/<package> builds.
# Sourced by the build, load and push scripts for those images.

# rpms_image_arches prints the arches each image is built for, and that its
# multi-arch manifest lists.
rpms_image_arches() {
  echo "amd64 arm64 ppc64le s390x"
}

# rpms_image_repo <package> prints the image repository, without a tag.
rpms_image_repo() {
  case "$1" in
    bird) echo calico/bird ;;
    nftables) echo calico/nftables-rpms ;;
    *)
      echo "Unknown package '$1': expected bird or nftables" >&2
      return 1
      ;;
  esac
}

# rpms_image_cache <package> prints the prefix of the image's tarball in the
# workflow cache.
rpms_image_cache() {
  case "$1" in
    bird) echo bird-image ;;
    nftables) echo nft-rpms ;;
    *)
      echo "Unknown package '$1': expected bird or nftables" >&2
      return 1
      ;;
  esac
}

# rpms_image_tag <package> prints the content-addressed tag, without an arch
# suffix.
rpms_image_tag() {
  make --no-print-directory -C "$(git rev-parse --show-toplevel)/hack/rpms/$1" print-tag
}
