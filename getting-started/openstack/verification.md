---
title: Verify your deployment
description: Quick steps to test that your Calico-based OpenStack deployment is running correctly.
canonical_url: '/getting-started/openstack/verification'
---

This document takes you through the steps you can perform to verify that
a {{site.prodname}}-based OpenStack deployment is running correctly.

## Prerequisites

This document requires you have the following things:

-   SSH access to the nodes in your {{site.prodname}}-based OpenStack deployment.
-   Access to an administrator account on your {{site.prodname}}-based
    OpenStack deployment.

## Procedure

Begin by creating several instances on your OpenStack deployment using
your administrator account. Confirm that these instances all launch and
correctly obtain IP addresses.

You'll want to make sure that your new instances are evenly striped
across your hypervisors. On your control node, run:

```bash
nova list --fields host
```

Confirm that there is an even spread across your compute nodes. If there
isn't, it's likely that an error has happened in either nova or {{site.prodname}}
on the affected compute nodes. Check the logs on those nodes for more
logging, and report your difficulty on the mailing list.

Now, SSH into one of your compute nodes. We're going to verify that the
FIB on the compute node has been correctly populated by {{site.prodname}}. To do
that, run the `route` command. You'll get output something like this:

```
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         net-vl401-hsrp- 0.0.0.0         UG    0      0        0 eth0
10.65.0.0       *               255.255.255.0   U     0      0        0 ns-b1163e65-42
10.65.0.103     npt06.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.104     npt09.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.105     *               255.255.255.255 UH    0      0        0 tap242f8163-08
10.65.0.106     npt09.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.107     npt07.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.108     npt08.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.109     npt07.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.110     npt06.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.111     npt08.datcon.co 255.255.255.255 UGH   0      0        0 eth0
10.65.0.112     *               255.255.255.255 UH    0      0        0 tap3b561211-dd
link-local      *               255.255.0.0     U     1000   0        0 eth0
172.18.192.0    *               255.255.255.0   U     0      0        0 eth0
```
{: .no-select-button}

You'll expect to see one route for each of the VM IP addresses in this
table. For VMs on other compute nodes, you should see that compute
node's IP address (or domain name) as the `gateway`. For VMs on this
compute node, you should see `*` as the `gateway`, and the tap interface
for that VM in the `Iface` field. As long as routes are present to all
VMs, the FIB has been configured correctly. If any VMs are missing from
the routing table, you'll want to verify the state of the BGP
connection(s) from the compute node hosting those VMs.

Having confirmed the FIB is present and correct, open the console for
one of the VM instances you just created. Confirm that the machine has
external connectivity by pinging `google.com` (or any other host you are
confident is routable and that will respond to pings). Additionally,
confirm it has internal connectivity by pinging the other instances
you've created (by IP).

If all of these tests behave correctly, your {{site.prodname}}-based OpenStack
deployment is in good shape.

## Troubleshooting

If you find that none of the advice below solves your problems, please
use our diagnostics gathering script to generate diagnostics, and then
raise a GitHub issue against our repository. To generate the diags, run:

```bash
/usr/bin/calico-diags
```

### VMs cannot DHCP

This can happen if your iptables is configured to have a default DROP
behaviour on the INPUT or FORWARD chains. You can test this by running
`iptables -L -t filter` and checking the output. You should see
something that looks a bit like this:

```
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  anywhere             anywhere            state RELATED,ESTABLISHED
ACCEPT     icmp --  anywhere             anywhere
ACCEPT     all  --  anywhere             anywhere
ACCEPT     tcp  --  anywhere             anywhere            state NEW tcp dpt:ssh
REJECT     all  --  anywhere             anywhere            reject-with icmp-host-prohibited

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
REJECT     all  --  anywhere             anywhere            reject-with icmp-host-prohibited

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```
{: .no-select-button}

The important sections are `Chain INPUT` and `Chain FORWARD`. Each of
those needs to have a policy of `ACCEPT`. In some systems, this policy
may be set to `DENY`. To change it, run `iptables -P <chain> ACCEPT`,
replacing `<chain>` with either `INPUT` or `FORWARD`.

Note that doing this may be considered a security risk in some networks.
A future {{site.prodname}} enhancement will remove the requirement to perform this
step.

### Routes are missing in the FIB.

If routes to some VMs aren't present when you run `route`, this suggests
that your BGP sessions are not functioning correctly. Your BGP daemon
should have either an interactive console or a log. Open the relevant
one and check that all of your BGP sessions have come up appropriately
and are replicating routes. If you're using a full mesh configuration,
confirm that you have configured BGP sessions with *all* other {{site.prodname}}
nodes.

### VMs Cannot Ping Non-VM IPs

Assuming all the routes are present in the FIB (see above), this most
commonly happens because the gateway is not configured with routes to
the VM IP addresses. To get full {{site.prodname}} functionality the gateway should
also be a BGP peer of the compute nodes (or the route reflector).

Confirm that your gateway has routes to the VMs. Assuming it does, make
sure that your gateway is also advertising those routes to its external
peers. It may do this using eBGP, but it may also be using some other
routing protocol.

### VMs Cannot Ping Other VMs

Before continuing, confirm that the two VMs are in security groups that
allow inbound traffic from each other (or are both in the same security
group which allows inbound traffic from itself). Traffic will not be
routed between VMs that do not allow inbound traffic from each other.

Assuming that the security group configuration is correct, confirm that
the machines hosting each of the VMs (potentially the same machine) have
routes to both VMs. If they do not, check out the troubleshooting
section [above](#routes-are-missing-in-the-fib).

### Web UI Shows Error Boxes Saying "Error: Unable to get quota info" and/or "Error: Unable to get volume limit"

This is likely a problem encountered with mapping devices in `cinder`,
OpenStack's logical volume management component. Many of these can be
resolved by restarting `cinder`.

```bash
service cinder-volume restart
service cinder-scheduler restart
service cinder-api restart
```

### Cannot create instances, error log says "could not open /dev/net/tun: Operation not permitted"

This is caused by having not restarted libvirt after you add lines to
the end of `/etc/libvirt/qemu.conf`. This can be fixed by either
rebooting your entire system or running:

```bash
service libvirt-bin restart
```
