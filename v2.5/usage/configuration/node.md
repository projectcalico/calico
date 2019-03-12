---
title: Configuring a Node IP Address and Subnet
canonical_url: 'https://docs.projectcalico.org/v3.6/usage/configuration/node'
---

By default, Calico automatically detects each Node's IP address and subnet.  In most cases, 
this auto-detection is enough and you will not need to change the value picked by Calico.  
However, there are some scenarios where the default autodetection may not choose the right
address.  For example:

-  Your host has multiple external interfaces.
-  Your host may have multiple IP addresses assigned to each interface.
-  You want to change the subnet configuration of each Node to use Calico's
   [cross-subnet IPIP]({{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip) feature.
-  You have changed the IP of your host.

This guide explains the various methods for configuring a Node's IP and subnet.

### Understanding `calico/node` IP Autodetection Logic

When `calico/node` is started, it determines the IP and subnet configuration using the
following sequence:

-  If an IP and subnet are explicitly specified using the `IP` (or `IP6`) environment variable (passed through
   to the container), the container will use this value *and* update the node 
   resource with that value: therefore a query of the node resource will always tell you what 
   value the calico/node container is currently using.
-  If the `IP` (or `IP6`) environment variable is set to `autodetect`, calico/node will autodetect
   the IP and subnet configuration using the requested autodetection method when the 
   container starts, *and* update the node resource with the detected value.
-  If the `IP` (or `IP6`) environment variable is not set, and there *is* an `IPv4Address` (or `IPv6Address`) 
   value configured in the node resource, that value will be used for routing.
-  If the `IP` environment variable is not set, and there is no `IPv4Address` value configured in the node
   resource, calico/node will autodetect an IPv4 address and subnet *and* update the
   node resource with the detected values so that the value is persisted.
-  If the `IP6` environment variable is not set, and there is no `IPv6Address` value configured in the node
   resource, calico/node will not perform IP6 routing on that node.

> If you are starting the calico/node container using `calicoctl node run` command,
> there is a direct mapping between the command line switches and the environment variables that are
> passed through to the `calico/node` container.  These are listed below:
> 
> | Environment | CLI |
> |-------------|-----|
> | IP | --ip |
> | IP6 | --ip6 |
> | IP_AUTODETECTION_METHOD | --ip-autodetection-method |
> | IP6_AUTODETECTION_METHOD | --ip6-autodetection-method |

The following subsections describe different ways to configure your deployment to
specify the IP addresses for your nodes.

#### a) Configure the IP and subnet through environment variables

The IPv4 address and subnet may be explicitly specified using the `--ip` option on 
`calicoctl node run` or the `IP` environment variable if you are starting the container
directly.  For IPv6, use the equivalent `--ip6` option and `IP6` environment variable.

If you omit the subnet, it is assumed to be /32 for IPv4 and /128 for IPv6 - it is
recommended to include the subnet information if you specify the IP addresses using
this approach.

For example (if using calicoctl node run):
```
calicoctl node run --ip=10.0.2.10/24
```

#### b) Autodetect the IP and subnet

The `calico/node` container can be configured to autodetect the IPv4 address and subnet everytime it
is restarted.  Use a value of `autodetect` for the IP address in the `--ip` option
on `calicoctl node run` or the `IP` environment variable if you are starting the container
directly.

In addition, the `--ip-autodetection-method` argument or the `IP_AUTODETECTION_METHOD`
environment variable can be used to specify the method used to auto detect the host address 
and subnet.  See [calico/node configuration guide]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
and [calicoctl command reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run)
for details.

For IPv6, use the equivalent `--ip6` and `--ip6-autodetection-method` options,
and `IP6` and `IP6_AUTODETECTION_METHOD` environment variables.

For example (if using calicoctl node run):
```
calicoctl node run --ip=autodetect --ip-autodetection-method=can-reach=8.8.8.8
```

#### c) Manually configure the node resource

The IP addresses may also be set by updating the node resource.

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
      ipv6Address: fd80:24e2:f998:72d6::/128

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
      ipv6Address: fd80:24e2:f998:72d6::/120
EOF
```

> Note that if you plan to edit the resource to configure the IP addresses, make sure 
> you are not specifying the IP address options or environment variables when starting the 
>`calico/node` container - otherwise those values will overwrite the values 
> configured through the resource.


