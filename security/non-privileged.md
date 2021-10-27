---
title: Run Calico in non-privileged and non-root containers
description: Run long-lived Calico components without root or system admin privileges.
---

### Big picture

Run long-lived {{site.prodname}} components in non-privileged and non-root containers.

### Value

In order to run {{site.prodname}} as securely as possible, long-running {{site.prodname}}
components such as `calico/node` can be run without privileged and root permissions in their
respective containers. In order to set up these long-running components, the init containers
will still need to run with privileged and root permissions but the risk to cluster security
they pose is minimal since they are ephemeral.

This comes at the cost of some network management functionality that allowed {{site.prodname}}
to correct any misconfigurations that other components running a cluster might create as well
as limited support for newer features being added to {{site.prodname}}. Running {{site.prodname}}
in non-privileged and non-root mode is for users who want to secure {{site.prodname}} as much
as possible who do not care for {{site.prodname}} features outside of basic {{site.prodname}}
networking and network policy.

### Before you begin

{{site.prodname}} running in non-privileged and non-root containers is only supported through
operator installations of {{site.prodname}}. Ensure that you are fine installing {{site.prodname}}
via the operator before continuing. The operator provides lifecycle management for {{site.prodname}}
exposed via the Kubernetes API defined as a custom resource definition.

The following features are not supported in non-privileged and non-root {{site.prodname}}:
* Any {{site.prodname}} Enterprise features
* eBPF dataplane

Feature support for features added after Calico v3.21 is also not guaranteed for {{site.prodname}}
running in non-privileged and non-root containers.

### How to

1. Follow the Tigera {{site.prodname}} operator [installation instructions](../getting-started/kuberneetes/quickstart).
   If you have already installed the operator, skip to the next step.

1. Edit the {{site.prodname}} installation to set the `nonPrivileged` field to `Enabled`.
   ```
   kubectl edit installation default
   ```
   Your installation resource should look similar to the following:
   ```
   apiVersion: operator.tigera.io/v1
   kind: Installation
   metadata:
     name: default
   spec:
     calicoNetwork:
       bgp: Enabled
       hostPorts: Enabled
       ipPools:
       - blockSize: 26
         cidr: 192.168.0.0/16
         encapsulation: VXLANCrossSubnet
         natOutgoing: Enabled
         nodeSelector: all()
       linuxDataplane: Iptables
       multiInterfaceMode: None
       nodeAddressAutodetectionV4:
         firstFound: true
     cni:
       ipam:
         type: Calico
       type: Calico
     controlPlaneReplicas: 2
     flexVolumePath: /usr/libexec/kubernetes/kubelet-plugins/volume/exec/
     nodeUpdateStrategy:
       rollingUpdate:
         maxUnavailable: 1
       type: RollingUpdate
     nonPrivileged: Enabled
     variant: Calico
   ```

1. The `calico-node` pods in the `calico-system` namespace should now restart. Verify that they restart properly.
   ```
   watch kubectl get pods -n calico-system
   ```

{{site.prodname}} should now be running `calico-node` in non-privileged and non-root containers.
