---
title: Run Calico node as non-privileged and non-root
description: Run long-lived Calico components without root or system admin privileges.
---

### Big picture

Run long-lived {{site.prodname}} components in non-privileged and non-root containers.

### Value

Running {{site.prodname}} in non-privileged and non-root mode is an option for users who
want to secure {{site.prodname}} as much as possible, and who do not care about
{{site.prodname}} features beyond the basic {{site.prodname}} networking and network policy.
The tradeoff for more security is the overhead of {{site.prodname}} networking management.
For example, you no longer receive {{site.prodname}} corrections to misconfigurations caused
by other components within your cluster, along with limited support for new features. 

### Concepts

To run {{site.prodname}} as securely as possible, long-running {{site.prodname}} components
(for example calico/node), can be run without privileged and root permissions in their respective
containers. Note that to set up these components, the init containers still need to run with
privileged and root permissions, but the risk to cluster security is minimal because of the
ephemeral nature of init containers.

### Supported

* Operator installation only.

### Unsupported

* {{site.prodname}} Enterprise
* eBPF dataplane

> **Note:** Support for features added after Calico v3.21 is not guaranteed.
{: .alert .alert-info }

### How to

1. Follow the Tigera {{site.prodname}} operator [installation instructions](../getting-started/kubernetes/quickstart).
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
