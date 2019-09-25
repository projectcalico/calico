---
title: Configure IP auto detection
---

### Big picture

Configure IP auto detection for calico nodes to ensure the correct IP address is used for routing.

### Value

When you install {{site.prodname}} on a node, an IP address and subnet is automatically detected using data from your datastore. {{site.prodname}} provides several ways to configure IP/subnet auto detection, and supports configuring specific IPs for:

- Hosts with multiple external interfaces
- Host interfaces with multiple IP addresses
- Changes to subnet for cross subnet feature for packet encapsulation
- Changes to host IP address

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Node** resource 

### Concepts

#### Auto detecting node IP address and subnet

For internode routing, each {{site.prodname}} node must be configured with an IPv4 address and/or an IPv6 address. When you install {{site.prodname}} on a node, a node resource is automatically created using default routing information from the datastore. For most deployments, you’ll want to update auto detection to ensure nodes get the correct IP address.

**Sample default node resource after installation**

```
apiVersion: projectcalico.org/v3
kind: Node
metadata:
  name: node-hostname
spec:
  bgp:
    asNumber: 64512
    ipv4Address: 10.244.0.1/24
    ipv6Address: 2000:db8:85a3::8a2e:370:7335/120
    ipv4IPIPTunnelAddr: 192.168.0.1
```

#### Auto detection methods 

By default, {{site.prodname}} uses the **first-found** method; the first valid IP address on the first interface (excluding local interfaces such as the docker bridge.) However, you can change the default method to any of these user-specified methods:

- IP addresses or domains (**can-reach**)
- regex to include matching interfaces (**interface**)
- regex to exclude matching interfaces (**skip-interface**)

For details on auto detection methods, see [calicoctl node run](https://docs.projectcalico.org/master/reference/calicoctl/node/run#ip-auto-detection-method-examples).

#### Manually configure IP address and subnet

There are two ways to manually configure an IP address and subnet:

- {{site.prodname}} node container (start/restart)
  Use environment variables and command line options to set values for nodes. 
- {{site.prodname}} node resource
  Update the node resource.

##### Using environment variables and node resource

Because you can configure IP address and subnet using either environment variables or node resource, the following table describes how values are synchronized. 

| **If these environment variables...** | **Are...**                                            | **Then...**                                                  |
| ------------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ |
| IP/IP6                                | Explicitly set                                        | The specified values are used, and the Node resource is updated. |
| IP/IP6                                | Set to auto detect                                     | Auto detects using the requested method (first-found, can-reach, interface, skip-interface), and updates the Node resource. |
| IP/IP6                                | Not set, but node resource has IP/IP6 values          | Node resource value is used.                                 |
| IP                                    | Not set, and there is no IP value in node resource    | Auto detects an IPv4 address and subnet, and updates Node resource. |
| IP6                                   | Not set, and there is a notIP6 value in Node resource | No IP6 routing is performed on the node.                     |

### How to

- [Change the auto detection method](#change-the-auto-detection-method)
- [Manually configure IP address and subnet for node](#manually-configure-ip-address-and-subnet-for-node)

#### Change the auto detection method

As noted, the default auto detection method is **first valid interface found** (first-found). To use a different auto detection method, use the {{site.prodnamedash}} node run command:

- **IPv4**

  ```calicoctl node run  --ip-autodetection-method=<autodetection-method>
  ``` 	
- **IPv6** 

  ```calicoctl node run --ip6-autodetection-method=<autodetection-method>
  ``` 	

Where <auto_detection> methods are:

- IP or domain name
  An IP addresses or domains to reach a destination. For example: 

  ```
     calicoctl node run  --ip-autodetection-method=can-reach=8.8.8.8
     calicoctl node run  --ip-autodetection-method=can-reach=www.google.com
  ```   

- regex expression to include matching interfaces
  A regular expression in golang syntax for including interfaces that match. For example:

  ```
     calicoctl node run  --ip-autodetection-method=interface=eth.*
  ```

- regex expression to exclude matching interfaces
  A regular expression in golang syntax for excluding the interfaces that match. For example:

  ```
     calicoctl node run --ip6-autodetection-method=skip-interface=eth.*
  ```

#### Manually configure IP address and subnet for a node

In the following scenarios, you may want to configure a specific IP and subnet:

- Hosts with multiple external interfaces
- Host interfaces with multiple IP addresses
- Changes to subnet for cross subnet feature for packet encapsulation
- Changes to host IP address

You configure specific IP address and subnet for a node using environment variables or updating the node resource.

##### Configure IP and subnet using environment variables

To configure IP and subnet values using environment variables, use the calicoctl node run command. For example:

```
   calicoctl node run --ip=10.0.2.10/24 --ip6=fd80:24e2:f998:72d6::/120
```

Where: 

- IP4 flag: --ip
- IP6 flag: --ip6

>**Note**: If the subnet is omitted, the defaults are: /32 (IPv4) and /128 (IPv6). We recommend that you include the subnet information for clarity when specifying IP addresses.
{: .alert .alert-info}


##### Configure IP and subnet using node resource

You can also set the IP address and subnet on a node resource. 

>**Tip**: When setting IP addresses on a node resource, you may want to disable IP address options or environment variables on the node. IP options on the container take precedence, and will overwrite the values you configure on the node resource.
{: .alert .alert-info}

Use **calicoctl** to query the current node configuration. For example:

```
   calicoctl get node node2 -o yaml
```

**Sample output**

```
- apiVersion: projectcalico.org/v3
  kind: Node
  metadata:
    name: node2
  spec:
    bgp:
      ipv4Address: 10.0.2.10/32
      ipv6Address: fd80:24e2:f998:72d6::/128
```

Next, reconfigure the node. Ror example, with an ipv4Address and subnet.

```
- apiVersion: projectcalico.org/v3
  kind: Node
  metadata:
    name: node2
  spec:
    bgp:
      ipv4Address: 10.0.2.10/24
      ipv6Address: fd80:24e2:f998:72d6::/120
```

### Above and beyond

- For details on all auto detection methods, see [calicoctl node run]({{site.baseurl}}/{{page.version}}/reference/calicoctl/node/run#ip-auto-detection-method-examples)
- For calicoctl environment variables, see [Configuring calico/node]({{site.baseurl}}/{{page.version}}/reference/node/configuration)