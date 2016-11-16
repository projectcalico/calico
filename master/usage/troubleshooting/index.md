---
title: Troubleshooting
---


## Common Installation Issues

#### Ubuntu (or GNOME) NetworkManager

Disable [NetworkManager](https://help.ubuntu.com/community/NetworkManager) before
attempting to use Calico networking.

NetworkManager manipulates the routing table for interfaces in the default network
namespace where Calico veth pairs are anchored for connections to containers.
This can interfere with the Calico agent's ability to route correctly.

You can configure interfaces in the `/etc/network/interfaces` file if the
NetworkManager removes your host's interfaces. See the Debian
[NetworkConfiguration](https://wiki.debian.org/NetworkConfiguration)
guide for more information.

## Common etcd Connection Issues

#### Running `sudo calicoctl ...` with Environment Variables

If you use `sudo` for commands like `calicoctl node run`, remember that your environment
variables will not be transferred to the `sudo` environment.  You can run `sudo` with
the `-E` flag to include your environment variables:

```shell
    sudo -E calicoctl node run
```

or you can set environment variables for `sudo` commands like this:

```shell
    sudo ETCD_ENDPOINTS=http://172.25.0.1:2379 calicoctl node run
```

Also be aware that connection information can be specified as a config
file rather than using environment variables.  See the
[Calicoctl Configuration Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup)
guide for details.

## Container Connectivity Issues

No matter what kind of connectivity issues you are having, we recommend you
**run through all of the following checks in order to diagnose the problem.**

#### Host Can't Communicate with its Containers

By default, hosts should be able to reach their running containers (even when policy would
otherwise prevent it). Test this basic connection by pinging a container IP from its host.

If this ping was not successful, check [Felix Logs](logging#felix) for issues.

#### Containers on the Same Host Can't Communicate

Containers on the same host should be able to ping one another, if policy allows it.
Testing this connection is usually orchestrator dependent. Browse the
[orchestrator-specific troubleshooting guides]({{site.baseurl}}/{{page.version}}/getting-started/)
for more information.

If the previous step was successful, but this step was not, it is likely that
the implemented policy is blocking the desired connection.

#### Containers Can't Communicate with the Internet

Containers with Calico IP's should be able to communicate with the Internet
provided that edge routers are correctly configured to NAT traffic from the Calico Pool.

Often in Cloud environments, edge routers will not be configured to perform this NAT,
and inbound responses will not be routed to the containers.

If you do not have the necessary privilege to enable NAT in your edge router,
Calico can perform NAT for traffic destined outside of the Calico Network. See
[Outbound Connectivity]({{site.baseurl}}/{{page.version}}/usage/external-connectivity#outbound-connectivity) for information on how to enable it.

#### Containers on Different Hosts Can't Communicate

If you have connectivity between containers on the same host, and between
containers and the Internet, but not between containers on different hosts, it
often indicates one of two problems:

1. Agents aren't sharing routes
2. Traffic is being dropped by the networking fabric

#### Hosts Aren't Sharing Routes

Each hosts routing table should be populated with routes to other hosts' containers.
Expect to see a `/26 via <other-host-ip>` on each Host. For example:
```
192.168.239.128/26 via 172.17.8.102 dev eth1  proto bird
```

If you do not see `/26`'s, Check BGP Connection Status by viewing the output of
`calicoctl node status` on each host.
Confirm that each host running containers has an "Established" BGP session:

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

If your connections are not Established, diagnose the BGP connection between the hosts.

- Can your hosts ping each other?  There must be IP connectivity between the
  hosts.

- Your hosts' names must be different.  Calico uses hostname as a key in the
  etcd data, and the etcd data is used to autogenerate the correct BIRD
  config - so a duplicate hostname will prevent correct BIRD setup.

- There must not be iptables rules, or any kind of firewall, preventing
  communication between the hosts on TCP port 179.  (179 is the BGP port.)

## Further Assistance

Still stuck? Collect diags with `sudo calicoctl node diags`, and raise an issu
on github or via the Calico Users Slack for further assistance.
