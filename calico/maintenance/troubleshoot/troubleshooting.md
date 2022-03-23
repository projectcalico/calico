---
title: Troubleshooting and diagnostics
description: View logs and diagnostics, common issues, and where to report issues in github.
canonical_url: '/maintenance/troubleshoot/troubleshooting'
---

### Logs and diagnostics

To collect diagnostics use the `calicoctl` command line tool using superuser privileges. For example:

```bash
sudo calicoctl node diags
```

To view logs, use the following command:

`kubectl logs -n calico-system <pod_name>`


To view debug logs on some Calico components, set the `LogSeverityScreen` through the associated environment variable. 


To report a problem, please [open an issue in GitHub](https://github.com/projectcalico/calico/issues){:target="_blank"}.


#### Check BGP peer status

If you have connectivity between containers on the same host, and between
containers and the Internet, but not between containers on different hosts, it
probably indicates a problem in your BGP configuration.

Look at `calicoctl node status` on each host.  It should include output like this:

```
Calico process is running.

IPv4 BGP status
+--------------+-------------------+-------+----------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |  SINCE   |    INFO     |
+--------------+-------------------+-------+----------+-------------+
| 172.17.8.102 | node-to-node mesh | up    | 23:30:04 | Established |
+--------------+-------------------+-------+----------+-------------+

IPv6 BGP status
No IPv6 peers found.
```
{: .no-select-button}

Alternatively, you can create a [`CalicoNodeStatus` resource]({{site.baseurl}}/reference/resources/caliconodestatus) to get BGP session status for the node.

If you do not see this, please check the following.

- Make sure there is IP connectivity between your hosts.

- Make sure your network allows the requisite BGP traffic on TCP port 179.

#### Configure NetworkManager

Configure [NetworkManager](https://help.ubuntu.com/community/NetworkManager){:target="_blank"} before
attempting to use {{site.prodname}} networking.

NetworkManager manipulates the routing table for interfaces in the default network
namespace where {{site.prodname}} veth pairs are anchored for connections to containers.
This can interfere with the {{site.prodname}} agent's ability to route correctly.

Create the following configuration file at `/etc/NetworkManager/conf.d/calico.conf` to prevent
NetworkManager from interfering with the interfaces:

```conf
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:tunl*;interface-name:vxlan.calico;interface-name:wireguard.cali
```

### Errors when running sudo calicoctl

If you use `sudo` for commands, remember that your environment variables are not transferred to the `sudo` environment.  You must run `sudo` with the `-E` flag to include your environment variables:

```bash
sudo -E calicoctl node diags
```

or you can set environment variables for `sudo` commands like this:

```bash
sudo ETCD_ENDPOINTS=http://172.25.0.1:2379 calicoctl node run
```

Also be aware that connection information can be specified as a config file rather than using environment variables.  See [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)
for details.

### Error: {{site.nodecontainer}} is not ready: BIRD is not ready: BGP not established with 10.0.0.1

In most cases, this "unready" status error in Kubernetes means that a particular peer is unreachable in the cluster. Check that BGP connectivity between the two peers is allowed in the environment.

This error can also occur if inactive Node resources are configured for node-to-node mesh. To fix this, [decommission the stale nodes]({{ site.baseurl }}/maintenance/decommissioning-a-node).

This error can also occur when BGP connections to non-mesh peers go down. If this is a common occurrence in your BGP topology, you can disable BIRD readiness checks. See [node readiness]({{ site.baseurl }}/reference/node/configuration#node-readiness)
for more information.


### Linux conntrack table is out of space 

A common problem on Linux systems is running out of space in the conntrack table, which can cause poor iptables performance. This can
happen if you run a lot of workloads on a given host, or if your workloads create a lot of TCP connections or bidirectional UDP streams. To avoid this problem, we recommend increasing the conntrack table size using the following commands:

    sysctl -w net.netfilter.nf_conntrack_max=1000000
    echo "net.netfilter.nf_conntrack_max=1000000" >> /etc/sysctl.conf
