# nftables / libnftnl RPMs

This directory builds the `calico/nftables-rpms` image consumed by the calico/node and istio install-cni image builds. It rebuilds two upstream packages as RPMs:

- **nftables** (GPL-2.0-only), pinned at 1.1.1 (see [#11750](https://github.com/projectcalico/calico/issues/11750)), with a single patch backported from upstream commit [be737a1](https://git.netfilter.org/nftables/commit/?id=be737a1986bfee0ddea4bee7863dca0123a2bcbc) ("src: netlink: fix crash when ops doesn't support udata"). See `patches/`.
- **libnftnl** (LGPL-2.1-or-later), rebuilt unmodified.

## Source availability

The binaries in the `calico/nftables-rpms` image (and the images that install RPMs from it) are built entirely from the pinned upstream release tarballs (versions and SHAs in `/metadata.mk`) plus the spec files and patches in this directory, which together are the complete corresponding source for the modified nftables. The upstream license text ships alongside the binaries via the RPMs' `%license` tag.
