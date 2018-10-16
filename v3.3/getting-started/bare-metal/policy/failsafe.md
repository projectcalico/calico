---
title: Failsafe rules
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/bare-metal/policy/failsafe'
---


To avoid completely cutting off a host via incorrect or malformed
policy, {{site.prodname}} has a failsafe mechanism that keeps various pinholes open
in the firewall.

By default, {{site.prodname}} keeps the following ports open on *all* host endpoints:

| Port   | Protocol | Direction           |              Purpose                           |
|--------|----------|---------------------|------------------------------------------------|
|   22   |   TCP    |  Inbound            |             SSH access                         |
|   53   |   UDP    |  Outbound           |             DNS queries                        |
|   67   |   UDP    |  Outbound           |             DHCP access                        |
|   68   |   UDP    |  Inbound            |             DHCP access                        |
|   179  |   TCP    |  Inbound & Outbound |             BGP access (Calico networking)     |
|   2379 |   TCP    |  Inbound & Outbound |             etcd access                        |
|   2380 |   TCP    |  Inbound & Outbound |             etcd access                        |
|   6666 |   TCP    |  Inbound & Outbound |             etcd self-hosted service access    |
|   6667 |   TCP    |  Inbound & Outbound |             etcd self-hosted service access    |


The lists of failsafe ports can be configured via the configuration parameters
`FailsafeInboundHostPorts` and `FailsafeOutboundHostPorts`
described in [Configuring
Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration).  They
can be disabled by setting each configuration value to "none".

> **Important**: Removing the inbound failsafe rules can leave a host inaccessible.
>
> Removing the outbound failsafe rules can leave Felix unable to connect
> to etcd.
>
> Before disabling the failsafe rules, we recommend creating a policy to
> replace it with more-specific rules for your environment: see 
> [Creating policy for basic connectivity](../policy/).
{: .alert .alert-danger}


