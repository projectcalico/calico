---
title: Encrypt in-cluster pod traffic
description: Enable WireGuard for state-of-the-art cryptographic security between pods for Calico clusters.
---

### Big picture

Enable WireGuard to secure on-the-wire, in-cluster pod traffic in a {{site.prodname}} cluster.

### Value

When this feature is enabled, {{ site.prodname }} automatically creates and manages WireGuard tunnels between nodes providing transport-level security for on-the-wire, in-cluster pod traffic. WireGuard provides {% include open-new-window.html text='formally verified' url='https://www.wireguard.com/formal-verification/' %} secure and {% include open-new-window.html text='performant tunnels' url='https://www.wireguard.com/performance/' %} without any specialized hardware. For a deep dive in to WireGuard implementation, see this {% include open-new-window.html text='whitepaper' url='https://www.wireguard.com/papers/wireguard.pdf' %}.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Felix configuration resource** with WireGuard configuration parameters

### Before you begin...

**Supported**

The following platforms using only IPv4:
- Kubernetes, on-premises
- EKS using Calico CNI
- EKS using AWS CNI
- AKS using Azure CNI

All platforms listed above will encrypt pod-to-pod traffic. Additionally, when using AKS or EKS, host-to-host traffic will also be encrypted, including host-networked pods.

- [Install and configure calicoctl]({{site.baseurl}}/maintenance/clis/calicoctl/install)
- Verify the operating system(s) running on the nodes in the cluster {% include open-new-window.html text='support WireGuard' url='https://www.wireguard.com/install/' %}.
- WireGuard in {{site.prodname}} requires node IP addresses to establish secure tunnels between nodes. {{site.prodname}} can automatically detect IP address of a node using [IP Setting]({{site.baseurl}}/reference/node/configuration#ip-setting) and [IP autodetection method]({{site.baseurl}}/reference/node/configuration#ip-autodetection-methods) in [calico/node]({{site.baseurl}}/reference/node/configuration) resource.
    - Set `IP` (or `IP6`) environment variable to `autodetect`.
    - Set `IP_AUTODETECTION_METHOD` (or `IP6_AUTODETECTION_METHOD`) to an appropriate value. If there are multiple interfaces on a node, set the value to detect the IP address of the primary interface.

### How to

- [Install WireGuard](#install-wireguard)
- [Enable WireGuard for a cluster](#enable-wireguard-for-a-cluster)
- [Disable WireGuard for an individual node](#disable-wireguard-for-an-individual-node)
- [Verify configuration](#verify-configuration)
- [Disable WireGuard for a cluster](#disable-wireguard-for-a-cluster)

#### Install WireGuard

WireGuard is included in Linux 5.6+ kernels, and has been backported to earlier Linux kernels in some Linux distributions.

Install WireGuard on cluster nodes using {% include open-new-window.html text='instructions for your operating system' url='https://www.wireguard.com/install/' %}. Note that you may need to reboot your nodes after installing WireGuard to make the kernel modules available on your system.

Use the following instructions for these platforms that are not listed on the WireGuard installation page, before proceeding to [enabling WireGuard](#enable-wireguard-for-a-cluster).

{% tabs %}
<label:EKS,active:true>
<%
To install WireGuard on the default Amazon Machine Image (AMI):

   ```bash
   sudo yum install kernel-devel-`uname -r` -y
   sudo yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
   sudo curl -o /etc/yum.repos.d/jdoss-wireguard-epel-7.repo https://copr.fedorainfracloud.org/coprs/jdoss/wireguard/repo/epel-7/jdoss-wireguard-epel-7.repo
   sudo yum install wireguard-dkms wireguard-tools -y
   ```

Additionally, you may optionally enable host-to-host encryption mode for WireGuard using the following command.

```bash
calicoctl patch felixconfiguration default --type='merge' -p '{"spec": {"wireguardHostEncryptionEnabled": true}}'
```

> **Warning**: `wireguardHostEncryptionEnabled` is an experimental flag that extends WireGuard encryption to host-network IP addresses. It is currently only supported on managed clusters deployed on EKS and AKS, where WireGuard *cannot* be enabled on the cluster's control-plane node. Enabling this flag while WireGuard is enabled on the control-plane node can lead to a broken cluster, and neworking deadlock.
{: .alert .alert-warning}

%>
<label:AKS>
<%
AKS cluster nodes run Ubuntu with a kernel that has WireGuard installed already, so there is no manual installation required.
However, you will need to enable host-to-host encryption mode for WireGuard using the following command.

```bash
calicoctl patch felixconfiguration default --type='merge' -p '{"spec": {"wireguardHostEncryptionEnabled": true}}'
```

> **Warning**: `wireguardHostEncryptionEnabled` is an experimental flag that extends WireGuard encryption to host-network IP addresses. It is currently only supported on managed clusters deployed on EKS and AKS, where WireGuard *cannot* be enabled on the cluster's control-plane node. Enabling this flag while WireGuard is enabled on the control-plane node can lead to a broken cluster, and neworking deadlock.
{: .alert .alert-warning}

%>
<label:OpenShift>
<%
To install WireGuard for OpenShift v4.8:


   1. Install requirements:
      - {% include open-new-window.html text='CoreOS Butane' url='https://coreos.github.io/butane/getting-started/' %}
      - {% include open-new-window.html text='Openshift CLI' url='https://docs.openshift.com/container-platform/4.2/cli_reference/openshift_cli/getting-started-cli.html' %}

   1. Download and configure the tools needed for kmods.
   ```bash
   FAKEROOT=$(mktemp -d)
   git clone https://github.com/tigera/kmods-via-containers
   cd kmods-via-containers
   make install FAKEROOT=${FAKEROOT}
   cd ..
   git clone https://github.com/tigera/kvc-wireguard-kmod
   cd kvc-wireguard-kmod
   make install FAKEROOT=${FAKEROOT}
   cd ..
   ```

   1. Configure/edit `${FAKEROOT}/root/etc/kvc/wireguard-kmod.conf`. 
   
       a. You must then set the URLs for the `KERNEL_CORE_RPM`, `KERNEL_DEVEL_RPM` and `KERNEL_MODULES_RPM` packages in the conf file `$FAKEROOT/etc/kvc/wireguard-kmod.conf`. Obtain copies for `kernel-core`, `kernel-devel`, and `kernel-modules` rpms from {% include open-new-window.html text='RedHat Access' url='https://access.redhat.com/downloads/content/package-browser' %} and host it in an http file server that is reachable by your OCP workers.

       b. For more details and help about configuring `kvc-wireguard-kmod/wireguard-kmod.conf`, see the {% include open-new-window.html text='kvc-wireguard-kmod README file' url='https://github.com/tigera/kvc-wireguard-kmod#quick-config-variables-guide' %}. Notes about wireguard version to kernel version compatibility is also available there.


   1. Get RHEL Entitlement data from your own RHEL8 system from a host in your cluster.
      ```bash
      tar -czf subs.tar.gz /etc/pki/entitlement/ /etc/rhsm/ /etc/yum.repos.d/redhat.repo
      ```
      Please refer to Openshift {% include open-new-window.html text='documentation' url='https://access.redhat.com/documentation/en-us/red_hat_subscription_management/1/html-single/rhsm/index#reg-cli' %} for more information about these entitlement files.

   1. Copy the `subs.tar.gz` file to your workspace and then extract the contents using the following command.
      ```bash
      tar -x -C ${FAKEROOT}/root -f subs.tar.gz
      ```

   1. Transpile your machine config using {% include open-new-window.html text='CoreOS Butane' url='https://coreos.github.io/butane/getting-started/' %}.
      ```bash
      cd kvc-wireguard-kmod
      make ignition FAKEROOT=${FAKEROOT} > mc-wg.yaml
      ```

   1. With the KUBECONFIG set for your cluster, run the following command to apply the MachineConfig which will install WireGuard across your cluster.
      ```bash
      oc create -f mc-wg.yaml
      ```
%>
{% endtabs %}

#### Enable WireGuard for a cluster

   > **Note**: Nodes that do not support WireGuard will not be secured by WireGuard tunnels, even if traffic running on the node to and from the pods goes to nodes that do support WireGuard.
   {: .alert .alert-info}

Enable WireGuard encryption across all the nodes using the following command.

```bash
calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
```

For OpenShift, add the Felix configuration with WireGuard enabled [under custom resources]({{site.baseurl}}/getting-started/openshift/installation#optionally-provide-additional-configuration).

   > **Note**: The above command can be used to change other WireGuard attributes. For a list of other WireGuard parameters and configuration evaluation, see the [Felix configuration]({{site.baseurl}}/reference/resources/felixconfig#felix-configuration-definition).
   {: .alert .alert-info}

We recommend that you review and modify the MTU used by Calico networking when WireGuard is enabled to increase network performance. Follow the instructions in the [Configure MTU to maximize network performance]({{site.baseurl}}/networking/mtu) guide to set the MTU to a value appropriate for your network.

#### Disable WireGuard for an individual node

To disable WireGuard on a specific node with WireGuard installed, modify the node-specific Felix configuration. e.g., to turn off encryption for pod traffic on node `my-node`, use the following command:

  ```bash
cat <<EOF | kubectl apply -f -
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: node.my-node
spec:
  logSeverityScreen: Info
  reportingInterval: 0s
  wireguardEnabled: false
EOF
  ```

With the above command, Calico will not encrypt any of the pod traffic to or from node `my-node`.

To enable encryption for pod traffic on node `my-node` again:

  ```bash
calicoctl patch felixconfiguration node.my-node --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
  ```

#### Verify configuration

To verify that the nodes are configured for WireGuard encryption, check the node status set by Felix using `calicoctl`. For example:

   ```
   $ calicoctl get node <NODE-NAME> -o yaml
   ...
   status:
     ...
     wireguardPublicKey: jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=
     ...
   ```

#### Disable WireGuard for a cluster

To disable WireGuard on all nodes modify the default Felix configuration. For example:

  ```bash
  calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
  ```

### Above and beyond

- [Secure Calico component communications]({{site.baseurl}}/security/comms)
- [Configure MTU to maximize network performance]({{site.baseurl}}/networking/mtu)
