---
title: AWS
---

Calico provides the following advantages when running in AWS:

- **Network Policy for Containers:** Calico provides fine-grained network security policy for individual containers.
- **No Overlays:** Within each VPC subnet Calico doesn't need an overlay, which means high performance networking for your containers.
- **No 50 Node Limit:** Calico allows you to surpass the 50 node limit, which exists as a consequence of the [AWS 50 route limit](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Appendix_Limits.html#vpc-limits-route-tables) when using the VPC routing table.

## Requirements

To deploy Calico in AWS, you must ensure that the proper security group rules
have been made and that traffic between containers on different hosts is not
dropped by the VPC. There are a few different options for doing this depending
on your deployment.

#### Configure Security Groups

Calico requires the following security group exceptions to function properly
in AWS.

| Description      | Type            | Protocol | Port Range |
|:-----------------|:----------------|:---------|:-----------|
| BGP              | Custom TCP Rule | TCP      | 179        |
| \*IPIP           | Custom Protocol | IPIP     | all        |

>\*IPIP: This rule is required only when using Calico with IPIP encapsulation.
Keep reading for information on when IPIP is required in AWS.

#### Routing Traffic Within a Single VPC Subnet

Since Calico assigns IP addresses outside the range used by AWS for EC2 instances, you must disable AWS src/dst
checks on each EC2 instance in your cluster
[as described in the AWS documentation](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck).  This
allows Calico to route traffic within a single VPC subnet without using an overlay.

#### Routing Traffic Across Different VPC Subnets / VPCs

If you need to split your deployment across multiple AZs for high availability then each AZ will have its own VPC subnet.  To
use Calico across multiple different VPC subnets or [peered VPCs](http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/vpc-peering.html),
in addition to disabling src/dst checks as described above you must also enable IPIP encapsulation and outgoing NAT
on your Calico IP pools.

See the [IP pool configuration reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
for information on how to configure Calico IP pools.

By default, Calico's IPIP encapsulation applies to all container-to-container traffic.  However,
encapsulation is only required for container traffic that crosses a VPC subnet boundary.  For better 
performance, you can configure Calico to perform IPIP encapsulation only across VPC subnet boundaries.  

To enable the "cross-subnet" IPIP feature, configure your Calico IP pool resources
to enable IPIP and set the mode to "cross-subnet".

> This feature was introduced in Calico v2.1, if your deployment was created with 
> an older version of Calico, or if you if you are unsure whether your deployment 
> is configured correctly, follow the steps in [Upgrading from pre-v2.1](#upgrading-from-pre-v21) before
> enabling "cross-subnet" IPIP.

The following `calicoctl` command will create or modify an IPv4 pool with 
CIDR 192.168.0.0/16 using IPIP mode `cross-subnet`. Adjust the pool CIDR for your deployment.

```
$ calicoctl apply -f - << EOF
apiVersion: v1
kind: ipPool
metadata:
  cidr: 192.168.0.0/16
spec:
  ipip:
    enabled: true
    mode: cross-subnet
EOF
```

#### Enabling Workload-to-WAN Traffic

To allow Calico networked containers to reach resources outside of AWS,
you must configure outgoing NAT on your [Calico IP pool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool).

AWS will perform outbound NAT on any traffic which has the source address of an EC2 virtual
machine instance.  By enabling outgoing NAT on your Calico IP pool, Calico will
NAT any outbound traffic from the containers hosted on the EC2 virtual machine instances.

The following `calicoctl` command will create or modify an IPv4 pool with 
CIDR 192.168.0.0/16 using IPIP mode `cross-subnet` and enables outgoing NAT.
Adjust the pool CIDR for your deployment.

```
$ calicoctl apply -f - << EOF
apiVersion: v1
kind: ipPool
metadata:
  cidr: 192.168.0.0/16
spec:
  ipip:
    enabled: true
    mode: cross-subnet
  nat-outgoing: true
EOF
```

## Upgrading from pre-v2.1

If you are planning to use cross-subnet IPIP, your deployment must be running with
Calico v2.1 or higher.  See [releases page]({{site.baseurl}}/{{page.version}}/releases) 
for details on the component versions for each release.

These instructions are primarily focussed around a non-orchestrated installation of
Calico - if you are using an orchestrator such as Kubernetes, you'll need to follow
the appropriate upgrade instructions for your orchestrator.  However, the instructions
below may be partially applicable.

#### Download calicoctl

Ensure you have the latest version of `calicoctl` downloaded. See [releases page]({{site.baseurl}}/{{page.version}}/releases) 
for the appropriate link.

The `calicoctl` should be downloaded to each node and to your management server (if you use one).

#### Upgrade your calico/node containers

Upgrade your `calico/node` container instances on each host. See [releases page]({{site.baseurl}}/{{page.version}}/releases) 
for details of the `calico/node` container version.

Any calico/node instance that was running prior to v2.1 will have incorrect
host subnet information configured (it will be /32 for the IPv4 management address).
It is important that the subnet configuration is correct prior to using the `cross-subnet`
IPIP feature.

You can verify which of your nodes is correctly configured using calicoctl.

Run `calicoctl get nodes --output=wide` to check the configuration.  e.g.

```
$ calicoctl get nodes --output=wide
NAME    ASN       IPV4           IPV6   
node1   (64512)   10.0.2.15/24          
node2   (64512)   10.0.2.10/32          
```

In this example, node1 has the correct subnet information whereas node2 needs
to be fixed.

The subnet configuration may be fixed in a few different ways depending on how 
you have deployed your calico/node containers.  We'll discuss the options below.

**Configure the IP and subnet through runtime args/environments**

The IP address may be explicitly specified using the `--ip` option on 
`calicoctl node run` or the `IP` environment if you are starting the container
directly.

If you are currently specifying the IP address, you will need to update the
parameter to include the network by specifying the IP and network in CIDR form (e.g. 
`10.0.2.10/24`).

For example (if using calicoctl node run):
```
calicoctl node run --ip=10.0.2.10/24
```


**Autodetect the IP and subnet**

The node can be instructed to autodetect the IP address and subnet everytime it
is restarted.  Use a value of `autodetect` for the IP address in the `--ip` option
on `calicoctl node run` or the `IP` environment if you are starting the container
directly.

In addition, the `--ip-autodetection-method` argument or the `IP_AUTODETECTION_METHOD`
environment can be used to specify the method used to auto detect the host address 
and subnet.  See [calico/node configuration guide]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
and [calicoctl command reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run)
for details.

For example (if using calicoctl node run):
```
calicoctl node run --ip=autodetect --ip-autodetection-method=can-reach=8.8.8.8
```

**Configure the IP and subnet on the node resource**

If the IP address is not being specified on the calico/node arguments or environments,
you can modify the node resource to have the correct subnet information.

You can use `calicoctl` to query the current configuration and then apply updates.
For example:

```
# Start by querying the current node configuration
$ calicoctl get node node2 -o yaml
- apiVersion: v1
  kind: node
  metadata:
    name: node2
  spec:
    bgp:
      ipv4Address: 10.0.2.10/32

# Now reconfigure the node with updated ipv4Address to include the correct
# subnet.
$ calicoctl apply -f - << EOF
- apiVersion: v1
  kind: node
  metadata:
    name: node2
  spec:
    bgp:
      ipv4Address: 10.0.2.10/24
EOF
```

#### Configure your IP pool

Once your system is upgraded and all of your subnet configuration is correct, you
may configure your IP pools as described above.