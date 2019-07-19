---
title: Protect hosts
---

### Big picture

Use Calico network policy to restrict traffic to/from hosts.

### Value

Restricting traffic between hosts and the outside world is not unique to Calico; many solutions provide this capability. However, the advantage of using Calico to protect the host is you can use the same Calico policy configuration as workloads. You only need to learn one tool. Write a cluster-wide policy, and it is immediately applied to every host. 

### Features

This how-to guide uses the following Calico features:

- **HostEndpoint** resource 
- **GlobalNetworkPolicy**
- **FelixConfiguration** resource with **FailsafeInboundHostPorts** and **DefaultEndpointToHostAction** parameters

### Concepts

#### Hosts and workloads

In the context of Calico configuration, a **workload** is a virtualized compute instance, like a VM or container. A **host** is the computer that runs the hypervisor (for VMs), or container runtime (for containers). We say it “hosts” the workloads as guests.

#### Host endpoints

Each host has one or more network interfaces that it uses to communicate externally. You can use Calico network policy to secure these interfaces (called host endpoints). Calico host endpoints can have labels, and they work the same as labels on workload endpoints. The network policy rules can apply to both workload and host endpoints using label selectors. 

#### Failsafe rules

It is easy to inadvertently cut all host connectivity because of non-existent or misconfigured network policy. To avoid this, Calico provides failsafe rules with default/configurable ports that are open on all host endpoints.

#### Default behavior of workload to host traffic

By default, Calico blocks all connections from a workload to its local host. You can control whether connections from a workload endpoint to its local host are dropped, returned, or accepted using a simple parameter.

Calico allows all connections from processes running on the host to guest workloads on the host. This allows host processes to run health checks and debug guest workloads.

#### Default behavior of external traffic to/from host

If a host endpoint is added and network policy is not in place, the Calico default is to deny traffic to/from that endpoint (except for traffic allowed by failsafe rules). For host endpoints, Calico blocks traffic only to/from interfaces that it’s been explicitly told about in network policy. Traffic to/from other interfaces is ignored.

#### Other host protection

In terms of design consistency in Calico, you may wonder about the following use cases.

**Does Calico protect a local host from workloads?**<br> 
Yes. DefaultEndpointToHostAction controls whether or not workloads can acesss their local host.<br>

**Does Calico protect a workload from the host it is running on?**<br> 
No. Calico allows connections the host makes to the workloads running on that host. Some orchestrators like Kubernetes depend on this connectivity for health checking the workload. Moreover, processes running on the local host are often privileged enough to override local Calico policy. Be very cautious with the processes you allow to run in the host's root network namespace.</br>

### Before you begin...

If you are already running Calico for Kubernetes, you are good to go. If you want to install Calico on a bare-metal machine for host protection only see, [Bare metal hosts]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/installation/binary-mgr).

### How to

- [Avoid accidentally cutting all host connectivity ](#avoid-accidentally-cutting-all-host-connectivity)
- [Use policy to restrict host traffic](#use-policy-to-restrict-host-traffic)
- [Control default behavior of workload endpoint to host traffic](#control-default-behavior-of-workload-endpoint-to-host-traffic)

#### Avoid accidentally cutting all host connectivity

To avoid inadvertently cut off all host connectivity because of non-existent or misconfigured network policy, Calico uses failsafe rules that open specific ports on all host endpoints. 

Review the following table to determine if the defaults work for your implementation. If not, change the default ports using the parameters, **FailsafeInboundHostPorts** and **FailsafeOutboundHostPorts** in [Configuring Felix]().

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

#### Use policy to restrict host traffic 

##### Step 1: Create policy to restrict host traffic

Although failsafe rules provide protection from removing all connectivity to a host, you should create a global network policy policy that restrict host traffic. 

In the following example, we use a **GlobalNetworkPolicy** that applies to all worker nodes (defined by a label). Ingress SSH access is allowed from a defined "management" subnet. 

**Ingress traffic** is also allowed for ICMP, and on TCP port 10250 (default kubelet port). **Egress** traffic is allowed to etcd on a particular IP, and UDP on port 53 and 67 for DNS and DHCP.

```
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

For each host point that you want to secure with policy, you must create a **host endpoint object**. To do that, you need the name of the Calico node on the host that owns the interface; in most cases, it is the same as the hostname of the host. 

In the following example, we create a host endpoint for the host named **my-host** with the interface named **eth0**, with **IP 10.0.0.1**. Note that the value for **node:** must match the hostname used on the Calico node object. 

When the host endpoint is created, traffic to or from the interface is dropped unless policy in place. 

```
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

The default Calico behavior blocks all connections from workloads to their local host (after traffic passes any egress policy applied to the workload). You can change this behavior using the **DefaultEndpointToHostAction** parameter in Felix configuration. 

This parameter works at the IP table level, where you can specify packet behavior to **Drop** (default), **Accept**, or **Return** (if you have your own rules in IP tables). 

To change this parameter for all hosts, edit the **FelixConfiguration** object named “default.”

1. Get a copy of the object to edit.  
   `calicoctl get felixconfiguration default --export -o yaml > default-felix-config.yaml`
1. Open the file in a text editor and add the parameter, **defaultEndpointToHostAction**. For example:
   ```
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
   `calicoctl apply -f default-felix-config.yaml`

### Above and beyond

- [Apply policy to Kubernetes nodeports]({{site.baseurl}}/{{page.version}}/security/kubernetesnodeports) 
- [Apply policy to services exposed externally as cluster IPs]({{site.baseurl}}/{{page.version}}/security/servicesclusterips) 
- [Apply policy to host forwarded traffic]({{site.baseurl}}/{{page.version}}/security/hostforwardedtraffic)  
- [Defend against DoS attacks]({{site.baseurl}}/{{page.version}}/security/defenddosattack) 
- [Felix configuration]({{site.baseurl}}/{{page.version}}/reference/resources/felixconfiguration) 
- [Global Network Policy]({{site.baseurl}}/{{page.version}}/reference/resources/globalnetworkpolicy) 
- [Host Endpoints]({{site.baseurl}}/{{page.version}}/reference/resources/hostendpoint)
