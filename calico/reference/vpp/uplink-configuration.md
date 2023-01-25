---
title: Primary interface configuration
description: Configuration parameters for the primary interface in VPP.
canonical_url: '/reference/vpp/uplink-configuration'
---

You can choose different ways to consume the host's primary interface with VPP, usually with a tradeoff between performance and simplicity of configuration. Here are the main supported configurations.

* `virtio` the interface is consumed with a native VPP driver. Performance is good and set up is simple, but only virtio interfaces are supported
* `avf` we create a virtual function and consume it with a native VPP driver. Performance is good and setup simple, but only intel AVF interfaces are supported
* `af_packet` the interface stays in Linux which passes packets to VPP. Performance is low, but it works out of the box with any interface
* `af_xdp` packets are passed via eBPF. This requires a `>=5.4` kernel, but works out of the box with good performance
* `dpdk` the interface is removed from Linux and consumed with the dpdk library. Performance and support are good, but setup can be complex
* other native VPP drivers bring better performance than `dpdk` but require complex manual setup

## General mechanics

The `calico-vpp-config` ConfigMap section of the manifest yaml contains the key `CALICOVPP_INTERFACES` which is a dictionary with parameters
specific to interfaces in calicovpp:


```yaml
 # Configures parameters for calicovpp agent and vpp manager
  CALICOVPP_INTERFACES: |-
    {
      "maxPodIfSpec": {
        "rx": 10, "tx": 10, "rxqsz": 1024, "txqsz": 1024
      },
      "defaultPodIfSpec": {
        "rx": 1, "tx":1, "isl3": true
      },
      "vppHostTapSpec": {
        "rx": 1, "tx":1, "rxqsz": 1024, "txqsz": 1024, "isl3": false
      },
      "uplinkInterfaces": [
        {
          "interfaceName": "eth1",
          "vppDriver": "af_packet"
        }
      ]
    }
```

The field `uplinkInterfaces` contains a list of interfaces and their configuration, with the first element being the primary/main interface, and the
rest (if any) being the secondary host interfaces. The way the primary interface gets configured is controlled by the `vppDriver` field in `uplinkInterfaces[0]`.
Leaving the `vppDriver` field empty (or unspecified) will try all drivers supported in your setup, starting with the most performant. You'll still
need to allocate hugepages if you want, for example, virtio to work.

> **Note**: `CALICOVPP_NATIVE_DRIVER` way of specifying the driver to use is still supported. Refer to **Legacy options** sub-section of [Getting Started]({{site.baseurl}}/getting-started/kubernetes/vpp/getting-started).
  {: .alert .alert-info}


## Using the native Virtio driver

You can use this driver if your primary interface is virtio [`realpath /sys/bus/pci/devices/<PCI_ID>/driver` gives `.../virtio-net`]

* Ensure you have hugepages available on your system (`sysctl -w vm.nr_hugepages=512`)
* Ensure `vfio-pci` is loaded (`sudo modprobe vfio-pci`)
* Set `vppDriver` as "virtio" in `uplinkInterfaces[0]`
* Also ensure that your vpp config has no `dpdk` stanza and its plugin disabled

Optionally if you would like to set the number/size of **rx** queues, refer to **UplinkInterfaceSpec** sub-section
of [Getting Started]({{site.baseurl}}/getting-started/kubernetes/vpp/getting-started).

## Using the native AVF driver

You can use this driver if your primary interface is supported by AVF [`realpath /sys/bus/pci/devices/<PCI_ID>/driver` gives `.../i40e`]

* Ensure `vfio-pci` is loaded (`sudo modprobe vfio-pci`)
* Set `vppDriver` as "avf" in `uplinkInterfaces[0]`
* Also ensure that your vpp config has no `dpdk` stanza and its plugin disabled

Optionally if you would like to set the number/size of **rx** queues, refer to **UplinkInterfaceSpec** sub-section
of [Getting Started]({{site.baseurl}}/getting-started/kubernetes/vpp/getting-started).

## Using AF_XDP

> **Caution:**  Ensure your kernel is at least `5.4` with `uname -r`
  {: .alert .alert-danger}

* Set `vppDriver` as "af_xdp" in `uplinkInterfaces[0]`
* Also ensure that your vpp config has no `dpdk` stanza and its plugin disabled
* Finally `FELIX_XDPENABLED` should be set to `false` on the `calico-node` container otherwise felix will periodically cleanup the VPP configuration
````yaml
---
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-node
  namespace: kube-system
spec:
  template:
    spec:
      containers:
        - name: calico-node
          env:
            - name: FELIX_XDPENABLED
              value: "false"
````
With kustomize use `kubectl kustomize ./yaml/overlays/af-xdp | kubectl apply -f -`

Optionally if you would like to set the number/size of **rx** queues or if you would like to customize whether we busy-poll the interface (`polling`),
only use interrupts to wake us up (`interrupt`) or switch between both depending on the load (`adaptive`), refer to **UplinkInterfaceSpec** sub-section
of [Getting Started]({{site.baseurl}}/getting-started/kubernetes/vpp/getting-started). 


#### Side notes

* AF_XDP won't start if you specify `buffers { buffers-per-numa }` to be too big (65536 should work)


## Using AF_PACKET

* Set `vppDriver` as "af_packet" in `uplinkInterfaces[0]`
* Also ensure that your vpp config has no `dpdk` stanza and the dpdk plugin is disabled

You can also use `kubectl kustomize ./yaml/overlays/af-packet | kubectl apply -f -`


## Using DPDK

### With hugepages

* Ensure you have hugepages available on your system (`sysctl -w vm.nr_hugepages=512`)
* Set `vppDriver` as "dpdk" in `uplinkInterfaces[0]`

### Without hugepages

DPDK can also run without hugepages but you would need to turn off **unsafe_iommu**, ie, you need to `echo N | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`,
and of course, you need to set `vppDriver` as "dpdk" in `uplinkInterfaces[0]`.


## Using native drivers with vpp's CLI

This is a rather advanced/experimental setup and we'll take the example of the AVF driver for this, using vpp cli, but any vpp driver can be used.
This allow to efficiently support other interface types.

* Set `vppDriver` as "none" in `uplinkInterfaces[0]`
* Ensure that your vpp config has no `dpdk` stanza and the dpdk plugin is disabled
* Lastly, in the vpp config add an `exec /etc/vpp/startup.exec` entry in `unix { .. }`

````yaml
vpp_config_template: |-
    unix {
      nodaemon
      full-coredump
      log /var/run/vpp/vpp.log
      cli-listen /var/run/vpp/cli.sock
      exec /etc/vpp/startup.exec
    }
    ...
    # removed dpdk { ... }
    ...
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
        plugin dpdk_plugin.so { disable }
    }
````

Then update the `CALICOVPP_CONFIG_EXEC_TEMPLATE` environment variable to pass the interface creation cli(s).

````yaml
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-vpp-node
  namespace: calico-vpp-dataplane
spec:
  template:
    spec:
      containers:
        - name: vpp
          env:
            - name: CALICOVPP_CONFIG_EXEC_TEMPLATE
              value: "create interface avf 0000:ab:cd.1 num-rx-queues 1"
````

In the specific case of the AVF driver, the PCI id must belong to a VF that can be created with the `avf.sh` [script](https://github.com/projectcalico/vpp-dataplane/blob/{{page.vppbranch}}/test/scripts/utils/avf.sh). Different drivers will have different requirements.
