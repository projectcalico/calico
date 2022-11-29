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

The main interface configuration is controlled by a variable named `CALICOVPP_NATIVE_DRIVER` that is passed to the `vpp` container.
You can edit the .yaml file as follows or use the overlays provided in `./yaml/overlays/*`.

By default, leaving `CALICOVPP_NATIVE_DRIVER` empty (or unspecified) will try all drivers supported in your setup, starting with the most performant. You'll still
need to allocate hugepages if you want e.g. Virtio to work.

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
            - name: CALICOVPP_NATIVE_DRIVER
              value: "af_packet"
````

For most deployments (except for DPDK) you should ensure that the vpp configuration stanza has DPDK disabled

````yaml
vpp_config_template: |-
    ...
    # removed dpdk { ... }
    ...
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
        plugin dpdk_plugin.so { disable }
    }
````

## Using the native Virtio driver

You can use this driver if your primary interface is virtio [`realpath /sys/bus/pci/devices/<PCI_ID>/driver` gives `.../virtio-net`]

* Ensure you have hugepages available on your system (`sysctl -w vm.nr_hugepages=256`)
* Ensure `vfio-pci` is loaded (`sudo modprobe vfio-pci`)

* Pass `CALICOVPP_NATIVE_DRIVER = virtio` to the `vpp` container
* Also ensure that your vpp config has no `dpdk` stanza and its plugin disabled
* Optionally `CALICOVPP_RX_QUEUES` controls the number of queues used, `CALICOVPP_RING_SIZE` their size

## Using the native AVF driver

You can use this driver if your primary interface is supported by AVF [`realpath /sys/bus/pci/devices/<PCI_ID>/driver` gives `.../i40e`]

* Ensure `vfio-pci` is loaded (`sudo modprobe vfio-pci`)

* Pass `CALICOVPP_NATIVE_DRIVER = avf` to the `vpp` container
* Also ensure that your vpp config has no `dpdk` stanza and its plugin disabled
* Optionally `CALICOVPP_RX_QUEUES` controls the number of queues used, `CALICOVPP_RING_SIZE` their size

## Using AF_XDP

> **Caution:**  Ensure your kernel is at least `5.4` with `uname -r`
  {: .alert .alert-danger}

* Pass `CALICOVPP_NATIVE_DRIVER = af_xdp` to the `vpp` container
* Also ensure that your vpp config has no `dpdk` stanza and its plugin disabled
* Optionally `CALICOVPP_RX_QUEUES` controls the number of queues used, `CALICOVPP_RING_SIZE` their size
* `CALICOVPP_RX_MODE` controls whether we busy-poll the interface (`polling`), only use interrupts to wake us up (`interrupt`) or switch between both depending on the load (`adaptive`)
* Finally `FELIX_XDPENABLED` should be set to `false` on the `calico-node` container otherwise felix will periodically cleanup the VPP configuration
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
            - name: CALICOVPP_NATIVE_DRIVER
              value: "af_xdp"
            - name: CALICOVPP_RING_SIZE
              value: "1024"
            - name: CALICOVPP_RX_QUEUES
              value: "1"
            - name: CALICOVPP_RX_MODE
              value: "polling"
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

#### Side nodes

* AF_XDP won't start if you specify `buffers { buffers-per-numa }` to be too big (65536 should work)

## Using AF_PACKET

* Pass `CALICOVPP_NATIVE_DRIVER = af_packet` to the `vpp` container
* Also ensure that your vpp config has no `dpdk` stanza and the dpdk plugin is disabled

You can also use `kubectl kustomize ./yaml/overlays/af-packet | kubectl apply -f -`

## Using DPDK

### With available hugepages

* Ensure you have hugepages available on your system (`sysctl -w vm.nr_hugepages=256`)
* Pass `CALICOVPP_NATIVE_DRIVER = none` to the `vpp` container
* The vpp config in the `calico-config` ConfigMap should look like the following, `__PCI_DEVICE_ID__` will be automatically populated with the PCI ID of `CALICOVPP_INTERFACE` at startup.
* `CALICOVPP_RX_QUEUES` and `CALICOVPP_RING_SIZE` have no more effect. They are controlled by their counterparts in the `dpdk {}` stanza namely `num-rx-queues` and `num-rx-desc`

````yaml
vpp_config_template: |-
    unix {
      nodaemon
      full-coredump
      cli-listen /var/run/vpp/cli.sock
    }
    api-trace { on }
    cpu {
        main-core 1
        workers 0
    }
    socksvr {
        socket-name /var/run/vpp/vpp-api.sock
    }
    dpdk {
      dev __PCI_DEVICE_ID__ { num-rx-queues 1  num-tx-queues 1 }
    }
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
    }
````

### Without hugepages

DPDK can also run without hugepages with the a configuration similar to the previous one
* Pass `CALICOVPP_NATIVE_DRIVER = none` to the `vpp` container
* The vpp config in the `calico-config` ConfigMap should look like the following, with `__PCI_DEVICE_ID__` automatically populated with that of `CALICOVPP_INTERFACE` at startup
* `CALICOVPP_RX_QUEUES` and `CALICOVPP_RING_SIZE` have no more effect. They are controlled by their counterparts in the `dpdk {}` stanza namely `num-rx-queues` and `num-rx-desc`

You also need to tell `dpdk` to no try allocating hugepages on its own
* `dpdk { no-hugetlb iova-mode va }` does this for the dpdk plugin
* `buffers { no-hugetlb }` does this for the buffers backing VPP's packets

> **Caution:**  This won't run with unsafe_iommu on. You need to `echo N | sudo tee /sys/module/vfio/parameters/enable_unsafe_noiommu_mode`
  {: .alert .alert-danger}

````yaml
vpp_config_template: |-
    unix {
      nodaemon
      full-coredump
      cli-listen /var/run/vpp/cli.sock
    }
    api-trace { on }
    cpu {
        main-core 1
        workers 0
    }
    socksvr {
        socket-name /var/run/vpp/vpp-api.sock
    }
    dpdk {
      dev __PCI_DEVICE_ID__ { num-rx-queues 1  num-tx-queues 1 }
      iova-mode va
      no-hugetlb
    }
    buffers {
      no-hugetlb
    }
    plugins {
        plugin default { enable }
        plugin calico_plugin.so { enable }
    }
````

## Using native drivers with vpp's CLI

This is a rather advanced/experimental setup, we'll take the example of the AVF driver for this, using vpp cli, but any vpp driver can be used. This allow to efficiently support other interface types.

* Pass `CALICOVPP_NATIVE_DRIVER = none` to the `vpp` container
* Same as before, you should remove the `dpdk { ... }` section in `vpp_config_template` and update the `plugins { ... }` definitions as follows
* Also add a `exec /etc/vpp/startup.exec` entry in `unix { .. }`

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
