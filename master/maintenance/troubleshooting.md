---
title: Troubleshooting
canonical_url: 'https://docs.projectcalico.org/v3.7/maintenance/troubleshooting'
---

* TOC
{:toc}

### Logs and diagnostics

To collect diagnostics use the `calicoctl` command line tool using superuser privileges. For example:

```bash
sudo calicoctl node diags
```

To view logs, use the following command:

`kubectl logs -n kube-system <pod_name>`


To view debug logs on some Calico components, set the `LogSeverityScreen` through the associated environment variable. 


To report a problem, please [open an issue in GitHub](https://github.com/projectcalico/calico/issues).


### Containers do not have network connectivity

#### Check for mismatched node names

If you notice that a workload has not received network connectivity, check
that the node name for that host is properly configured. The name for the [node resource](../reference/resources/node) must match
the node name in the [workload endpoint resources](../reference/resources/workloadendpoint) on that host. If the names are mismatched,
it is likely that all workloads on that node will not receive networking.

To check this, query one of the broken workload endpoints and check its node name:

	calicoctl get workloadendpoints -n <namespace>

Then, check to see if a single corresponding node resource exists:

	calicoctl get nodes

If the node resource either does not exist or there are multiple node resources representing the bad node, it is likely that the node's hostname has changed. This often happens
as a result of switching a node's hostname between its FQDN and its short DNS name.

To correct this, you must perform the following steps (with examples shown using Kubernetes):

1. Prevent new workloads from being scheduled on the bad node.
```
kubectl cordon mynode.internal.projectcalico.org
```
1. Drain all workloads from the node.
```
kubectl drain mynode.internal.projectcalico.org --ignore-daemonsets
```
1. On the bad node, set the hostname to the desired value.
```
sudo hostnamectl set-hostname <desired-hostname>
```
1. Delete the bad node configuration from {{site.prodname}}.
```
calicoctl delete node <name-of-bad-node>
```
1. Restart {{site.nodecontainer}} on the bad node to pick up the changes.
```
kubectl delete pod -n kube-system <name-of-calico-pod>
```
1. Reenable scheduling of worklods on the node.
```
kubectl uncordon mynode.internal.projectcalico.org
```

To prevent this problem from occurring, we recommend always mounting the `/var/lib/calico` directory into the `{{site.nodecontainer}}`
container when installing {{site.prodname}}. This allows all components to detect and use the same node name. See
[node name determination](../reference/node/configuration#node-name-determination) for more information.

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

If you do not see this, please check the following.

- Make sure there is IP connectivity between your hosts.

- Make sure your network allows the requisite BGP traffic on TCP port 179.

#### Configure NetworkManager

Configure [NetworkManager](https://help.ubuntu.com/community/NetworkManager) before
attempting to use {{site.prodname}} networking.

NetworkManager manipulates the routing table for interfaces in the default network
namespace where {{site.prodname}} veth pairs are anchored for connections to containers.
This can interfere with the {{site.prodname}} agent's ability to route correctly.

Create the following configuration file at `/etc/NetworkManager/conf.d/calico.conf` to prevent
NetworkManager from interfering with the interfaces:

```
[keyfile]
unmanaged-devices=interface-name:cali*;interface-name:tunl*
```

### Errors when running sudo calicoctl

If you use `sudo` for commands like `calicoctl node run`, remember that your environment variables are not transferred to the `sudo` environment.  You must run `sudo` with the `-E` flag to include your environment variables:

```shell
sudo -E calicoctl node run
```

or you can set environment variables for `sudo` commands like this:

```shell
sudo ETCD_ENDPOINTS=http://172.25.0.1:2379 calicoctl node run
```

Also be aware that connection information can be specified as a config file rather than using environment variables.  See [Installing calicoctl](../getting-started/calicoctl/install)
for details.

### Error: {{site.nodecontainer}} is not ready: BIRD is not ready: BGP not established with 10.0.0.1

In most cases, this "unready" status error in Kubernetes means that a particular peer is unreachable in the cluster. Check that BGP connectivity between the two peers is allowed in the environment.

This error can also occur if inactive Node resources are configured for node-to-node mesh. To fix this, [decommission the stale nodes](../maintenance/decommissioning-a-node).

This error can also occur when BGP connections to non-mesh peers go down. If this is a common occurrence in your BGP topology, you can disable BIRD readiness checks. See [node readiness]({{site.baseurl}}/{{page.version}}/reference/node/configuration#node-readiness)
for more information.


### Linux conntrack table is out of space 

A common problem on Linux systems is running out of space in the conntrack table, which can cause poor iptables performance. This can
happen if you run a lot of workloads on a given host, or if your workloads create a lot of TCP connections or bidirectional UDP streams. To avoid this problem, we recommend increasing the conntrack table size using the following commands:

    sysctl -w net.netfilter.nf_conntrack_max=1000000
    echo "net.netfilter.nf_conntrack_max=1000000" >> /etc/sysctl.conf
