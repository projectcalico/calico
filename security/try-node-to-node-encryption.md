---
title: Try out the node-to-node encryption tech preview
description: Try out enabling WireGuard for state-of-the-art cryptographic security between pods for Calico clusters.
---

### Big picture

Enable WireGuard to secure node-to-node traffic in a {{site.prodname}} cluster.

> **Warning!** Node-to-node encryption is a tech preview and should not be used in production clusters. It has had very limited testing and it will contain bugs (please report these on the Calico Users Slack or GitHub). This feature is currently not supported with overlay networks (IP in IP, VXLAN) due to known issues with NodePort services.
{: .alert .alert-danger }

### Value

{{ site.prodname }} supports WireGuard tunnels between nodes providing transport-level security for node-to-node traffic. WireGuard provides [formally verified](https://www.wireguard.com/formal-verification/) secure and [performant tunnels](https://www.wireguard.com/performance/) without any specialized hardware. For a deep dive in to WireGuard implementation, see [whitepaper](https://www.wireguard.com/papers/wireguard.pdf).

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Felix configuration resource** with WireGuard configuration parameters.

### Before you begin...

- Verify the operating system(s) running on the nodes in the cluster [support WireGuard](https://www.wireguard.com/install/).

    >**Note**: WireGuard in {{site.prodname}} does not support IPv6 at this time.
    {: .alert .alert-info}
- In the tech preview release, node-to-node encryption is supported on an underlying network that doesn’t require Calico to use an overlay. For example, a cluster with a routed network topology.

### How to

1. Install WireGuard on cluster nodes using these [instructions for your operating system](https://www.wireguard.com/install/).

   >**Note**: Nodes that do not support WireGuard will not be secured by WireGuard tunnels, even if traffic running on the node to and from the pods goes to nodes that do support WireGuard.
   {: .alert .alert-info}

1. Enable WireGuard encryption across all the nodes using the following command.

   ```
   calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
   ```

For OpenShift, add the Felix configuration with WireGuard enabled [under custom resources]({{ site.baseurl }}/getting-started/openshift/installation#optionally-provide-additional-configuration).

>**Note**: This above command can be used to change other WireGuard attributes. For a list of other WireGuard parameters and configuration evaluation, see the [Felix configuration]({{ site.baseurl }}/reference/resources/felixconfig#felix-configuration-definition).
   {: .alert .alert-info}

To disable WireGuard on a specific node with WireGuard installed, modify the host-specific Felix configuration. For example:
```
calicoctl patch felixconfiguration <Host-Name> --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
```

#### Troubleshooting

- To verify that the nodes are configured for WireGuard encryption, check the node status set by Felix using `calicoctl`. For example:

   ```
   $ calicoctl get node <NODE-NAME> -o yaml
   ...
   status:
     ..
     wireguardPublicKey: jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=
     ...
   ```

### Above and beyond

- [Secure Calico component communications]({{ site.baseurl }}/security/comms)

