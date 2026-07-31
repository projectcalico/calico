# calico/third-party-cni-plugins

Image containing the upstream CNI plugins that Calico installs onto each node:

- `host-local`, `portmap`, `loopback`, `tuning` from
  [projectcalico/containernetworking-plugins](https://github.com/projectcalico/containernetworking-plugins)
- `flannel` from
  [projectcalico/flannel-cni-plugin](https://github.com/projectcalico/flannel-cni-plugin)

The image is intended to be used as an init container in the `calico-node`
DaemonSet. Its entrypoint copies the plugin binaries from `/plugins/` into a
shared volume (default `/stage/`), which the `install-cni` init container then
mounts at `/opt/cni/bin` and copies onto the host. The plugins ship as a
separate image rather than being baked into `calico/calico` so that the main
image stays small.

Versions of the upstream sources are pinned via `CNI_VERSION` and
`FLANNEL_VERSION` in `metadata.mk`.

This component lives under `third_party/` to mark the plugin source as not
ours. The Calico-specific wrapper (Dockerfile, entrypoint, Makefile) is in
this directory.
