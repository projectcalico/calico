---
title: Configure IP autodetection
description: Calico IP autodetection ensures the correct IP address is used for routing. Learn how to customize it. 
---

### Big picture

Configure IP autodetection for {{site.prodname}} nodes to ensure the correct IP address is used for routing.

### Value

When you install {{site.prodname}} on a node, an IP address and subnet is automatically detected. {{site.prodname}} provides several ways to configure IP/subnet autodetection, and supports configuring specific IPs for:

- Hosts with multiple external interfaces
- Host interfaces with multiple IP addresses
- [Changes to cross subnet packet encapsulation]({{ site.baseurl }}/networking/vxlan-ipip)
- Changes to host IP address

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Node** resource

### Concepts

#### Autodetecting node IP address and subnet

For internode routing, each {{site.prodname}} node must be configured with an IPv4 address and/or an IPv6 address. When you install {{site.prodname}} on a node, a node resource is automatically created using routing information that is detected from the host. For some deployments, you may want to update autodetection to ensure nodes get the correct IP address.

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

#### Autodetection methods

By default, {{site.prodname}} uses the **first-found** method; the first valid IP address on the first interface (excluding local interfaces such as the docker bridge). However, you can change the default method to any of the following:

- Address assigned to Kubernetes node (**kubernetes-internal-ip**)
- Address used by the node to reach a particular IP or domain (**can-reach**)
- Regex to include matching interfaces (**interface**)
- Regex to exclude matching interfaces (**skip-interface**)
- A list of IP ranges in CIDR format to determine valid IP addresses on the node to choose from (**cidrs**)

For more details on autodetection methods, see [node configuration]({{ site.baseurl }}/reference/node/configuration) reference.

### How to

- [Change the autodetection method](#change-the-autodetection-method)
- [Manually configure IP address and subnet for a node](#manually-configure-ip-address-and-subnet-for-a-node)

#### Change the autodetection method

{% tabs %}
  <label:Operator,active:true>
<%
As noted previously, the default autodetection method is **first valid interface found** (first-found). To use a different autodetection method, edit the default [Installation]({{site.baseurl}}/reference/installation/api#operator.tigera.io/v1.Installation) custom resource, specifying the method. Below are examples of the supported autodetection methods:

> **Note**: To configure the default autodetection method for IPv6 for any of the below methods, use the field `nodeAddressAutodetectionV6`.
{: .alert .alert-info}

- **Kubernetes Node IP**

  {{site.prodname}} will select the first internal IP address listed in the Kubernetes node's `Status.Addresses` field.

  ```
  kind: Installation
  apiVersion: operator.tigera.io/v1
  metadata:
    name: default
  spec:
    calicoNetwork:
      nodeAddressAutodetectionV4:
        kubernetes: NodeInternalIP
  ```
 
- **Source address used to reach an IP or domain name**

  {{site.prodname}} will choose the IP address that is used to reach the given "can reach" IP address or domain. For example:

  ```
  kind: Installation
  apiVersion: operator.tigera.io/v1
  metadata:
    name: default
  spec:
    calicoNetwork:
      nodeAddressAutodetectionV4:
        canReach: 8.8.8.8
  ```

- **Including matching interfaces**

  {{site.prodname}} will choose an address on each node from an interface that matches the given [regex](https://pkg.go.dev/regexp){:target="_blank"}.
  For example:

  ```
  kind: Installation
  apiVersion: operator.tigera.io/v1
  metadata:
    name: default
  spec:
    calicoNetwork:
      nodeAddressAutodetectionV4:
        interface: eth.*
  ```

- **Excluding matching interfaces**

  {{site.prodname}} will choose an address on each node from an interface that does not match the given [regex](https://pkg.go.dev/regexp){:target="_blank"}.
  For example:

  ```
  kind: Installation
  apiVersion: operator.tigera.io/v1
  metadata:
    name: default
  spec:
    calicoNetwork:
      nodeAddressAutodetectionV4:
        skipInterface: eth.*
  ```

- **Including CIDRs**

  {{site.prodname}} will select any IP address from the node that falls within the given CIDRs. For example:

  ```
  kind: Installation
  apiVersion: operator.tigera.io/v1
  metadata:
    name: default
  spec:
    calicoNetwork:
      nodeAddressAutodetectionV4:
        cidrs:
          - "192.168.200.0/24"
  ```
%>
  <label:Manifest>
<%
As noted previously, the default autodetection method is **first valid interface found** (first-found). To use a different autodetection method, use the following `kubectl set env` command, specifying the method:

- **IPv4**

  ```
  kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=<autodetection-method>
  ```

- **IPv6**

  ```
  kubectl set env daemonset/calico-node -n kube-system IP6_AUTODETECTION_METHOD=<autodetection-method>
  ```

Where autodetection methods are based on:

- **Kubernetes Node IP**

  {{site.prodname}} will select the first internal IP address listed in the Kubernetes node's `Status.Addresses` field.

  ```
  kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=kubernetes-internal-ip
  ```

- **Source address used to reach an IP or domain name**

  {{site.prodname}} will choose the IP address that is used to reach the given "can reach" IP address or domain. For example:

  ```
  kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=can-reach=www.google.com
  ```

- **Including matching interfaces**

  {{site.prodname}} will choose an address on each node from an interface that matches the given [regex](https://pkg.go.dev/regexp){:target="_blank"}.
  For example:

  ```
  kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=interface=eth.*
  ```

- **Excluding matching interfaces**

  {{site.prodname}} will choose an address on each node from an interface that does not match the given [regex](https://pkg.go.dev/regexp){:target="_blank"}.
  For example:

  ```
  kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=skip-interface=eth.*
  ```
  
- **Including CIDRs**

  {{site.prodname}} will select any IP address from the node that falls within the given CIDRs. For example:

  ```
  kubectl set env daemonset/calico-node -n kube-system IP_AUTODETECTION_METHOD=cidr=192.168.200.0/24,172.15.0.0/24
  ```
%>
{% endtabs %}

#### Manually configure IP address and subnet for a node

In the following scenarios, you may want to configure a specific IP and subnet:

- Hosts with multiple external interfaces
- Host interfaces with multiple IP addresses
- Changes to cross subnet packet encapsulation
- Changes to host IP address

{% tabs %}
  <label:Operator,active:true>
<%

You can configure specific IP address and subnet for a node by disabling IP autodetection and then updating the [Node resource]({{ site.baseurl }}/reference/resources/node).

##### Disable autodetection

To disable autodetection method, update the proper `NodeAddressAutodetection` field in the Installation resource:

```yaml
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
spec:
  calicoNetwork:
    nodeAddressAutodetectionV4: {}
    nodeAddressAutodetectionV4: {}
```

##### Configure IP and subnet using node resource

You can configure the IP address and subnet on a Node resource.

Use `calicoctl patch` to update the current node configuration. For example:

```
calicoctl patch node kind-control-plane \
  --patch='{"spec":{"bgp": {"ipv4Address": "10.0.2.10/24", "ipv6Address": "fd80:24e2:f998:72d6::/120"}}}'
```

%>
  <label:Manifest>
<%
You can configure specific IP address and subnet for a node using environment variables or by updating the [Node resource]({{ site.baseurl }}/reference/resources/node). Because you can configure IP address and subnet using either environment variables or node resource, the following table describes how values are synchronized.

| **If this environment variable...** | **Is...**                                             | **Then...**                                                  |
| ----------------------------------- | ----------------------------------------------------- | ------------------------------------------------------------ |
| IP/IP6                              | Explicitly set                                        | The specified values are used, and the Node resource is updated. |
|                                     | Set to autodetect                                     | The requested method is used (first-found, can-reach, interface, skip-interface, kubernetes-internal-ip), and the Node resource is updated. |
|                                     | Not set, but Node resource has IP/IP6 values          | Node resource value is used.                                 |
| IP                                  | Not set, and there is no IP value in Node resource    | Autodetects an IPv4 address and subnet, and updates Node resource. |
| IP6                                 | Not set, and there is a no IP6 value in Node resource | No IP6 routing is performed on the node.                     |

##### Configure IP and subnet using environment variables

To configure IP and subnet values using environment variables, use a `kubectl set env` command. For example:

```
kubectl set env daemonset/calico-node -n kube-system IP=10.0.2.10/24 IP6=fd80:24e2:f998:72d6::/120
```

>**Note**: If the subnet is omitted, the defaults are: /32 (IPv4) and /128 (IPv6). We recommend that you include the subnet information for clarity when specifying IP addresses.
{: .alert .alert-info}

##### Configure IP and subnet using node resource

You can also configure the IP address and subnet on a Node resource.

>**Tip**: When configuring the IP address on a Node resource, you may want to disable IP address options or environment variables on the node. IP options on the container take precedence, and will overwrite the values you configure on the node resource.
{: .alert .alert-info}

Use `calicoctl patch` to update the current node configuration. For example:

```
calicoctl patch node kind-control-plane \
  --patch='{"spec":{"bgp": {"ipv4Address": "10.0.2.10/24", "ipv6Address": "fd80:24e2:f998:72d6::/120"}}}'
```
%>
{% endtabs %}

### Above and beyond

- For details on autodetection methods, see the [node configuration]({{ site.baseurl }}/reference/node/configuration) reference.
- For calicoctl environment variables, see [Configuring {{site.nodecontainer}}]({{ site.baseurl }}/reference/node/configuration)
- [Node resource]({{ site.baseurl }}/reference/resources/node)
- [Reference documentation for calicoctl patch]({{ site.baseurl }}/reference/calicoctl/patch)
