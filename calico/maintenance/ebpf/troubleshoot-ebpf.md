---
title: Troubleshoot eBPF mode
description: How to troubleshoot when running in eBPF mode. 
canonical_url: '/maintenance/ebpf/troubleshoot-ebpf'
---

This document gives some general troubleshooting guidance for the eBPF dataplane.

### Troubleshoot access to services

If pods or hosts within your cluster have trouble accessing services, check the following:

* Either {{site.prodname}}'s eBPF mode or `kube-proxy` must be active on a host for services to function.  If you
  disabled `kube-proxy` when enabling  eBPF mode, verify that eBPF mode is actually functioning.  If {{site.prodname}}
  detects that the kernel is not supported, it will fall back to standard dataplane mode (which does not support 
  services).
  
  To verify that eBPF mode is correctly enabled, examine the log for a `{{site.noderunning}}` container; if
  eBPF mode is not supported it will log an `ERROR` log that says 
  
      BPF dataplane mode enabled but not supported by the kernel.  Disabling BPF mode.
      
  If BPF mode is correctly enabled, you should see an `INFO` log that says
  
      BPF enabled, starting BPF endpoint manager and map manager.
      
* In eBPF mode, external client access to services (typically NodePorts) is implemented using VXLAN encapsulation.
  If NodePorts time out when the backing pod is on another node, check your underlying network fabric allows
  VXLAN traffic between the nodes.  VXLAN is a UDP protocol; by default it uses port 4789.
  
* In DSR mode, {{site.prodname}} requires that the underlying network fabric allows one node to respond on behalf of
  another.
  
    * In AWS, to allow this, the Source/Dest check must be disabled on the node's NIC.  However, note that DSR only
      works within AWS; it is not compatible with external traffic through a load balancer.  This is because the load 
      balancer is expecting the traffic to return from the same host.
    
    * In GCP, the "Allow forwarding" option must be enabled. As with AWS, traffic through a load balancer does not
      work correctly with DSR because the load balancer is not consulted on the return path from the backing node.
      
### Check if a program is dropping packets

To check if an eBPF program is dropping packets, you can use the `tc` command-line tool.  For example, if you
are worried that the eBPF program attached to `eth0` is dropping packets, you can run the following command:

```
tc -s qdisc show dev eth0
``` 
The output should look like the following; find the `clsact` qdisc, which is the attachment point for eBPF programs.
The `-s` option to `tc` causes `tc` to display the count of dropped packets, which amounts to the count of packets 
dropped by the eBPF programs. 
```
...
qdisc clsact 0: dev eth0 root refcnt 2 
 sent 1340 bytes 10 pkt (dropped 10, overlimits 0 requeues 0) 
 backlog 0b 0p requeues 0
...
```

### Debug high CPU usage

If you notice `{{site.noderunning}}` using high CPU:

* Check if `kube-proxy` is still running.  If `kube-proxy` is still running, you must either disable `kube-proxy` or
  ensure that the Felix configuration setting `bpfKubeProxyIptablesCleanupEnabled` is set to `false`.  If the setting
  is set to `true` (its default), then Felix will attempt to remove `kube-proxy`'s iptables rules.  If `kube-proxy` is
  still running, it will fight with `Felix`.
  
* If your cluster is very large, or your workload involves significant service churn, you can increase the interval
  at which Felix updates the services dataplane by increasing the `bpfKubeProxyMinSyncPeriod` setting. The default is
  1 second.  Increasing the value has the trade-off that service updates will happen more slowly.
  
* {{site.prodname}} supports endpoint slices, similarly to `kube-proxy`.  If your Kubernetes cluster supports endpoint
  slices and they are enabled, then you can enable endpoint slice support in {{site.prodname}} with the 
  `bpfKubeProxyEndpointSlicesEnabled` configuration flag.
  
### eBPF program debug logs

{{site.prodname}}'s eBPF programs contain optional detailed debug logging.  Although th logs can be very verbose (because
the programs will log every packet), they can be invaluable to diagnose eBPF program issues.  To enable the log, set the 
`bpfLogLevel` Felix configuration setting to `Debug`.  

 >**WARNING!** Enabling logs in this way has a significant impact on eBPF program performance.
{: .alert .alert-danger}

The logs are emitted to the kernel trace buffer, and they can be examined using the following command:
```
tc exec bpf debug
```
Logs have the following format:
```
     <...>-84582 [000] .Ns1  6851.690474: 0: ens192---E: Final result=ALLOW (-1). Program execution time: 7366ns
```

The parts of the log are explained below:

* `<...>-84582` gives an indication about what program (or kernel process) was handling the 
  packet.  For packets that are being sent, this is usually the name and PID of the program that is actually sending 
  the packet.  For packets that are received, it is typically a kernel process, or an unrelated program that happens to
  trigger the processing.
  
* `6851.690474` is the log timestamp.

* `ens192---E` is the {{site.prodname}} log tag. For programs attached to interfaces, the first part contains the 
  first few characters of the interface name.  The suffix is either `-I` or `-E` indicating "Ingress" or "Egress".
  "Ingress" and "Egress" have the same meaning as for policy:
  
    * A workload ingress program is executed on the path from the host network namespace to the workload.
    * A workload egress program is executed on the workload to host path.
    * A host endpoint ingress program is executed on the path from external node to the host.
    * A host endpoint egress program is executed on the path from host to external host.  
    
* `Final result=ALLOW (-1). Program execution time: 7366ns` is the message.  In this case, logging the final result of 
  the program.  Note that the timestamp is massively distorted by the time spent logging.

## The `calico-bpf` tool

Since BPF maps contain binary data, the {{site.prodname}} team wrote a tool to examine {{site.prodname}}'s BPF maps.
The tool is embedded in the {{site.nodecontainer}} container image. To run the tool:

* Find the name of the {{site.nodecontainer}} Pod on the host of interest using
  ```bash
  kubectl get pod -o wide -n calico-system
  ```
  for example, `calico-node-abcdef`

* Run the tool as follows:
  ```bash
  kubectl exec -n calico-system calico-node-abcdef -- calico-node -bpf ...
  ```
  For example, to show the tool's help:
  ```bash
  $ kubectl exec -n calico-system calico-node-abcdef -- calico-node -bpf help
   
  Usage:
    calico-bpf [command]
  
  Available Commands:
    arp          Manipulates arp
    connect-time Manipulates connect-time load balancing programs
    conntrack    Manipulates connection tracking
    help         Help about any command
    ipsets       Manipulates ipsets
    nat          Nanipulates network address translation (nat)
    routes       Manipulates routes
    version      Prints the version and exits
  
  Flags:
    --config string   config file (default is $HOME/.calico-bpf.yaml)
    -h, --help            help for calico-bpf
    -t, --toggle          Help message for toggle
  ```
  (Since the tool is embedded in the main `calico-node` binary the `--help` option is not available, but running
  `calico-node -bpf help` does work.)

  To dump the BPF conntrack table:
  ```
  $ kubectl exec -n calico-system calico-node-abcdef -- calico-node -bpf conntrack dump
  ...
  ```

### Poor performance

A number of problems can reduce the performance of the eBPF dataplane.

* Verify that you are using the best networking mode for your cluster.  If possible, avoid using an overlay network;
  a routed network with no overlay is considerably faster. If you must use one of {{site.prodname}}'s overlay modes, 
  use VXLAN, not IPIP.  IPIP performs poorly in eBPF mode due to kernel limitations.
  
* If you are not using an overlay, verify that the [Felix configuration parameters](../../reference/felix/configuration) 
  `ipInIpEnabled` and `vxlanEnabled` are set to `false`.  Those parameters control whether Felix configured itself to 
  allow IPIP or VXLAN, even if you have no IP pools that use an overlay.  The parameters also disable certain eBPF 
  mode optimisations for compatibility with IPIP and VXLAN.
  
  To examine the configuration:
  ```bash
  kubectl get felixconfiguration -o yaml
  ```
  
  ```yaml
  apiVersion: projectcalico.org/v3
  items:
  - apiVersion: projectcalico.org/v3
    kind: FelixConfiguration
    metadata:
      creationTimestamp: "2020-10-05T13:41:20Z"
      name: default
      resourceVersion: "767873"
      uid: 8df8d751-7449-4b19-a4f9-e33a3d6ccbc0
    spec:
      ...
      ipipEnabled: false
      ...
      vxlanEnabled: false
  kind: FelixConfigurationList
  metadata:
    resourceVersion: "803999"
  ```

* If you are running your cluster in a cloud such as AWS, then your cloud provider may limit the bandwidth between
  nodes in your cluster.  For example, most AWS nodes are limited to 5GBit per connection.

