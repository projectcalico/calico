---
title: Istio integration
canonical_url: 'https://docs.projectcalico.org/master/getting-started/kubernetes/installation/hardway/istio-integration'
---

{{site.prodname}} policy integrates with [Istio](https://istio.io) to allow you to write policies that enforce against
application layer attributes like HTTP methods or paths as well as against cryptographically secure identities. In this
lab we will enable this integration and test it out.

## Install FlexVolume driver

{{site.prodname}} uses a FlexVolume driver to enable secure connectivity between Felix and the Dikastes container
running in each pod.  It mounts a shared volume into which Felix inserts a Unix Domain Socket.

On each node in the cluster, execute the following commands to install the FlexVolume driver binary.

```
sudo mkdir -p /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds
sudo docker run --rm \
  -v /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds:/host/driver \
  calico/pod2daemon-flexvol:v3.8.0
```

Verify the `uds` binary is present

```bash
ls -lh /usr/libexec/kubernetes/kubelet-plugins/volume/exec/nodeagent~uds
```

Result

```
total 5.0M
-r-xr-x--- 1 root root 5.0M Jul 25 22:31 uds
```
{: .no-select-button}

## Enable application layer policy

Your cluster is now ready to enable application layer policy, and you can do so using [the standard instructions](/{{page.version}}/getting-started/kubernetes/installation/app-layer-policy).

## Test application layer policy

You can test application layer policy by following the [Application Layer Policy tutorial](/{{page.version}}/security/app-layer-policy/).

