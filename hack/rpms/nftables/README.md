# nftables / libnftnl RPMs

This directory builds the `calico/nftables-rpms` image consumed by the calico/node and istio install-cni image builds. It rebuilds two upstream packages as RPMs:

- **nftables** (GPL-2.0-only), pinned at 1.1.1 (see [#11750](https://github.com/projectcalico/calico/issues/11750)), with a single patch backported from upstream commit [be737a1](https://git.netfilter.org/nftables/commit/?id=be737a1986bfee0ddea4bee7863dca0123a2bcbc) ("src: netlink: fix crash when ops doesn't support udata"). See `patches/`.
- **libnftnl** (GPL-2.0-or-later), rebuilt from unpatched upstream source.

## Source availability

Both packages are built entirely from the pinned upstream release tarballs (versions and SHAs in `metadata.mk` at the repo root) plus the spec files and patches in this directory, which together are the complete corresponding source. The producer image stashes the upstream tarballs, our patches, and the spec files under `/src`; calico/node and the istio install-cni image copy that into `/included-source`, so the corresponding source for the GPL binaries ships in the image alongside them (next to the BIRD and Felix GPL source). The upstream license text also ships via the RPMs' `%license` tag.
