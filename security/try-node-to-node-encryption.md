---
title: Try out the pod-to-pod encryption tech preview
description: Try out enabling WireGuard for state-of-the-art cryptographic security between pods for Calico clusters.
---

### Big picture

Enable WireGuard to secure on the wire pod-to-pod traffic in a {{site.prodname}} cluster.

> **Warning!** Pod-to-pod encryption is a tech preview and should not be used in production clusters. It has had very limited testing and it will contain bugs (please report these on the Calico Users Slack or GitHub). This feature is currently not supported with overlay networks (IP in IP or VXLAN) due to known issues with NodePort services.
{: .alert .alert-danger}

### Value

{{ site.prodname }} automatically creates and manages WireGuard tunnels between nodes providing transport-level security for on the wire pod-to-pod traffic. WireGuard provides {% include open-new-window.html text='formally verified' url='https://www.wireguard.com/formal-verification/' %} secure and {% include open-new-window.html text='performant tunnels' url='https://www.wireguard.com/performance/' %} without any specialized hardware. For a deep dive in to WireGuard implementation, see {% include open-new-window.html text='whitepaper' url='https://www.wireguard.com/papers/wireguard.pdf' %}.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Felix configuration resource** with WireGuard configuration parameters

### Before you begin...

Verify the operating system(s) running on the nodes in the cluster {% include open-new-window.html text='support WireGuard' url='https://www.wireguard.com/install/' %}.

> **Note**: WireGuard in {{site.prodname}} does not support IPv6 at this time.
{: .alert .alert-info}

> **Note**: In the tech preview release, pod-to-pod encryption is supported on an underlying network that doesn’t require {{site.prodname}} to use an overlay. For example, a cluster with a routed network topology. 
{: .alert .alert-info}

### How to

1. Install WireGuard on cluster nodes using these {% include open-new-window.html text='instructions for your operating system' url='https://www.wireguard.com/install/' %}.

   > **Note**: Nodes that do not support WireGuard will not be secured by WireGuard tunnels, even if traffic running on the node to and from the pods goes to nodes that do support WireGuard. 
   {: .alert .alert-info}

1. Enable WireGuard encryption across all the nodes using the following command.
    ```
     calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
    ```
   For OpenShift, add the Felix configuration with WireGuard enabled [under custom resources]({{ site.baseurl }}/getting-started/openshift/installation#optionally-provide-additional-configuration).    

   > **Note**: The above command can be used to change other WireGuard attributes. For a list of other WireGuard parameters and configuration evaluation, see the [Felix configuration]({{ site.baseurl }}/reference/resources/felixconfig#felix-configuration-definition).
   {: .alert .alert-info}

To disable WireGuard on a specific node with WireGuard installed, modify the host-specific Felix configuration. For example:

  ```
  calicoctl patch felixconfiguration <Host-Name> --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
  ```
#### Troubleshoot

To verify that the nodes are configured for WireGuard encryption, check the node status set by Felix using `calicoctl`. For example:

   ```
   $ calicoctl get node <NODE-NAME> -o yaml
   ...
   status:
     ...
     wireguardPublicKey: jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=
     ...
   ```
### Above and beyond

- [Secure Calico component communications]({{ site.baseurl }}/security/comms)
