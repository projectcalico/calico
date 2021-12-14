---
title: Protect hosts
description: Calico network policy not only protects workloads, but also hosts. Create a Calico network policies to restrict traffic to/from hosts.
---

### Big picture

Use {{site.prodname}} network policy to restrict traffic to/from hosts.

### Value

Restricting traffic between hosts and the outside world is not unique to {{site.prodname}}; many solutions provide this capability. However, the advantage of using {{site.prodname}} to protect the host is you can use the same {{site.prodname}} policy configuration as workloads. You only need to learn one tool. Write a cluster-wide policy, and it is immediately applied to every host.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **HostEndpoint** resource
- **GlobalNetworkPolicy**
- **FelixConfiguration** resource with parameters:
  - **FailsafeInboundHostPorts**
  - **DefaultEndpointToHostAction**

### Concepts

#### Hosts and workloads

In the context of {{site.prodname}} configuration, a **workload** is a virtualized compute instance, like a VM or container. A **host** is the computer that runs the hypervisor (for VMs), or container runtime (for containers). We say it “hosts” the workloads as guests.

#### Host endpoints

Each host has one or more network interfaces that it uses to communicate externally. You can use {{site.prodname}} network policy to secure these interfaces (called host endpoints). {{site.prodname}} host endpoints can have labels, and they work the same as labels on workload endpoints. The network policy rules can apply to both workload and host endpoints using label selectors.

#### Failsafe rules

It is easy to inadvertently cut all host connectivity because of non-existent or misconfigured network policy. To avoid this, {{site.prodname}} provides failsafe rules with default/configurable ports that are open on all host endpoints.

#### Default behavior of workload to host traffic

By default, {{site.prodname}} blocks all connections from a workload to its local host. You can control whether connections from a workload endpoint to its local host are dropped, returned, or accepted using a simple parameter.

{{site.prodname}} allows all connections from processes running on the host to guest workloads on the host. This allows host processes to run health checks and debug guest workloads.

#### Default behavior of external traffic to/from host

If a host endpoint is added and network policy is not in place, the {{site.prodname}} default is to deny traffic to/from that endpoint (except for traffic allowed by failsafe rules). For host endpoints, {{site.prodname}} blocks traffic only to/from interfaces that it’s been explicitly told about in network policy. Traffic to/from other interfaces is ignored.

#### Other host protection

In terms of design consistency in {{site.prodname}}, you may wonder about the following use cases.

**Does {{site.prodname}} protect a local host from workloads?**<br>
Yes. DefaultEndpointToHostAction controls whether or not workloads can acesss their local host.<br>

**Does {{site.prodname}} protect a workload from the host it is running on?**<br>
No. {{site.prodname}} allows connections the host makes to the workloads running on that host. Some orchestrators like Kubernetes depend on this connectivity for health checking the workload. Moreover, processes running on the local host are often privileged enough to override local {{site.prodname}} policy. Be very cautious with the processes that you allow to run in the host's root network namespace.

### Before you begin...

If you are already running {{site.prodname}} for Kubernetes, you are good to go. If you want to install {{site.prodname}} on a non-cluster machine for host protection only, see [Non-cluster hosts]({{ site.baseurl }}/getting-started/bare-metal/).

### How to

- [Avoid accidentally cutting all host connectivity ](#avoid-accidentally-cutting-all-host-connectivity)
- [Use policy to restrict host traffic](#use-policy-to-restrict-host-traffic)
- [Control default behavior of workload endpoint to host traffic](#control-default-behavior-of-workload-endpoint-to-host-traffic)

#### Avoid accidentally cutting all host connectivity

To avoid inadvertently cutting all host connectivity because of non-existent or misconfigured network policy, {{site.prodname}} uses failsafe rules that open specific ports and CIDRs on all host endpoints.

Review the following table to determine if the defaults work for your implementation. If not, change the default ports using the parameters, **FailsafeInboundHostPorts** and **FailsafeOutboundHostPorts** in [Configuring Felix]({{ site.baseurl }}/reference/felix/configuration#environment-variables).

| Port   | Protocol | CIDR       | Direction           |              Purpose                           |
|--------|----------|------------|---------------------|------------------------------------------------|
|   22   |   TCP    |  0.0.0.0/0 |  Inbound            |             SSH access                         |
|   53   |   UDP    |  0.0.0.0/0 |  Outbound           |             DNS queries                        |
|   67   |   UDP    |  0.0.0.0/0 |  Outbound           |             DHCP access                        |
|   68   |   UDP    |  0.0.0.0/0 |  Inbound            |             DHCP access                        |
|   179  |   TCP    |  0.0.0.0/0 |  Inbound & Outbound |             BGP access ({{site.prodname}} networking)     |
|   2379 |   TCP    |  0.0.0.0/0 |  Inbound & Outbound |             etcd access                        |
|   2380 |   TCP    |  0.0.0.0/0 |  Inbound & Outbound |             etcd access                        |
|   6443 |   TCP    |  0.0.0.0/0 |  Inbound & Outbound |             Kubernetes API server access       |
|   6666 |   TCP    |  0.0.0.0/0 |  Inbound & Outbound |             etcd self-hosted service access    |
|   6667 |   TCP    |  0.0.0.0/0 |  Inbound & Outbound |             etcd self-hosted service access    |

#### Use policy to restrict host traffic

##### Step 1: Create policy to restrict host traffic

Although failsafe rules provide protection from removing all connectivity to a host, you should create a GlobalNetworkPolicy policy that restricts host traffic.

In the following example, we use a **GlobalNetworkPolicy** that applies to all worker nodes (defined by a label). Ingress SSH access is allowed from a defined "management" subnet.

**Ingress traffic** is also allowed for ICMP, and on TCP port 10250 (default kubelet port). **Egress** traffic is allowed to etcd on a particular IP, and UDP on port 53 and 67 for DNS and DHCP.

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: k8s-worker
spec:
  selector: "role == 'k8s-worker'"
  order: 0
  ingress:
  - action: Allow
    protocol: TCP
    source:
      nets:
      - "<your management CIDR>"
    destination:
      ports: [22]
  - action: Allow
    protocol: ICMP
  - action: Allow
    protocol: TCP
    destination:
      ports: [10250]
  egress:
  - action: Allow
    protocol: TCP
    destination:
      nets:
      - "<your etcd IP>/32"
      ports: [2379]
  - action: Allow
    protocol: UDP
    destination:
      ports: [53, 67]
 ```

##### Step 2: Create host endpoints

For each host point that you want to secure with policy, you must create a **HostEndpoint** object. To do that, you need the name of the {{site.prodname}} node on the host that owns the interface; in most cases, it is the same as the hostname of the host.

In the following example, we create a HostEndpoint for the host named **my-host** with the interface named **eth0**, with **IP 10.0.0.1**. Note that the value for **node:** must match the hostname used on the {{site.prodname}} node object.

When the HostEndpoint is created, traffic to or from the interface is dropped unless policy is in place.

```yaml
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: my-host-eth0
  labels:
    role: k8s-worker
    environment: production
spec:
  interfaceName: eth0
  node: my-host
  expectedIPs: ["10.0.0.1"]
```

#### Control default behavior of workload endpoint to host traffic

The default {{site.prodname}} behavior blocks all connections from workloads to their local host (after traffic passes any egress policy applied to the workload). You can change this behavior using the **DefaultEndpointToHostAction** parameter in Felix configuration.

This parameter works at the IP table level, where you can specify packet behavior to **Drop** (default), **Accept**, or **Return**.

To change this parameter for all hosts, edit the **FelixConfiguration** object named “default.”

1. Get a copy of the object to edit.

   ```bash
   calicoctl get felixconfiguration default --export -o yaml > default-felix-config.yaml
   ```
1. Open the file in a text editor and add the parameter, **defaultEndpointToHostAction**. For example:

   ```yaml
   apiVersion: projectcalico.org/v3
   kind: FelixConfiguration
   metadata:
     name: default
   spec:
     ipipEnabled: true
     logSeverityScreen: Info
     reportingInterval: 0s
     defaultEndpointToHostAction: Accept
   ```

1. Update the FelixConfiguration on the cluster.
   ```bash
   calicoctl apply -f default-felix-config.yaml
   ```

### Above and beyond

- [Apply policy to Kubernetes node ports]({{ site.baseurl }}/security/kubernetes-node-ports)
- [Protect Kubernetes nodes with host endpoints managed by {{site.prodname}}]({{ site.baseurl }}/security/kubernetes-nodes)
- [Defend against DoS attacks]({{ site.baseurl }}/security/defend-dos-attack)
- [Global network policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- [Host endpoint]({{ site.baseurl }}/reference/resources/hostendpoint)
