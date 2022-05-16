---
title: Felix configuration
description: API for this Calico resource.
canonical_url: '/reference/resources/felixconfig'
---

A [Felix]({{ site.baseurl }}/reference/architecture/overview#felix) configuration resource (`FelixConfiguration`) represents Felix configuration options for the cluster.

See [Configuring Felix]({{ site.baseurl }}/reference/felix/configuration) for more details.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: default
spec:
  ipv6Support: false
  ipipMTU: 1400
  chainInsertMode: Append
```

### Felix configuration definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |

- {{site.prodname}} automatically creates a resource named `default` containing the global default configuration settings for Felix. You can use [calicoctl]({{ site.baseurl }}/reference/calicoctl/overview) to view and edit these settings
- The resources with the name `node.<nodename>` contain the node-specific overrides, and will be applied to the node `<nodename>`. When deleting a node the FelixConfiguration resource associated with the node will also be deleted.

#### Spec

| Field                              | Description                 | Accepted Values   | Schema | Default    |
|------------------------------------|-----------------------------|-------------------|--------|------------|
| awsSrcDstCheck                     | Controls automatically setting {% include open-new-window.html text='source-destination-check' url='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck' %} on an AWS EC2 instance running Felix. Setting the value to `Enable` will set the check value in the instance description to `true`. For `Disable`, the check value will be `false`. Setting must be `Disable` if you want the EC2 instance to process traffic not matching the host interface IP address. For example, EKS cluster using Calico CNI with `VXLANMode=CrossSubnet`. Check [IAM role and profile configuration](#aws-iam-rolepolicy-for-source-destination-check-configuration) for setting the necessary permission for this setting to work.| DoNothing, Enable, Disable | string | `DoNothing` |
| chainInsertMode                    | Controls whether Felix hooks the kernel's top-level iptables chains by inserting a rule at the top of the chain or by appending a rule at the bottom. `Insert` is the safe default since it prevents {{site.prodname}}'s rules from being bypassed.  If you switch to `Append` mode, be sure that the other rules in the chains signal acceptance by falling through to the {{site.prodname}} rules, otherwise the {{site.prodname}} policy will be bypassed. | Insert, Append | string | `Insert` |
| dataplaneWatchdogTimeout | Timeout before the main dataplane goroutine is determined to have hung and Felix will report non-live and non-ready.  Can be increased if the liveness check incorrectly fails (for example if Felix is running slowly on a heavily loaded system). | `90s`, `120s`, `10m` etc. | duration | `90s` |
| defaultEndpointToHostAction        | This parameter controls what happens to traffic that goes from a workload endpoint to the host itself (after the traffic hits the endpoint egress policy).  By default {{site.prodname}} blocks traffic from workload endpoints to the host itself with an iptables "DROP" action. If you want to allow some or all traffic from endpoint to host, set this parameter to `Return` or `Accept`.  Use `Return` if you have your own rules in the iptables "INPUT" chain; {{site.prodname}} will insert its rules at the top of that chain, then `Return` packets to the "INPUT" chain once it has completed processing workload endpoint egress policy.  Use `Accept` to unconditionally accept packets from workloads after processing workload endpoint egress policy. | Drop, Return, Accept | string | `Drop` |
| deviceRouteSourceAddress           | IPv4 address to set as the source hint for routes programmed by Felix. When not set the source address for local traffic from host to workload will be determined by the kernel. | IPv4 | string | `""` |
| deviceRouteSourceAddressIPv6       | IPv6 address to set as the source hint for routes programmed by Felix. When not set the source address for local traffic from host to workload will be determined by the kernel. | IPv6 | string | `""` |
| deviceRouteProtocol                | This defines the route protocol added to programmed device routes. | Protocol | int | RTPROT_BOOT |
| failsafeInboundHostPorts           | UDP/TCP/SCTP protocol/cidr/port groupings that Felix will allow incoming traffic to host endpoints on irrespective of the security policy. This is useful to avoid accidentally cutting off a host with incorrect configuration.  The default value allows SSH access, etcd, BGP, DHCP and the Kubernetes API. |  | List of [ProtoPort](#protoport) | {::nomarkdown}<p><code>- protocol: tcp<br>&nbsp;&nbsp;port: 22<br>- protocol: udp<br>&nbsp;&nbsp;port: 68<br>- protocol: tcp<br>&nbsp;&nbsp;port: 179<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2379<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2380<br>- protocol: tcp<br>&nbsp;&nbsp;port: 5473<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6443<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6666<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6667</code></p>{:/} |
| failsafeOutboundHostPorts          | UDP/TCP/SCTP protocol/port groupings that Felix will allow outgoing traffic from host endpoints to irrespective of the security policy. This is useful to avoid accidentally cutting off a host with incorrect configuration.  The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd as well as allowing DHCP, DNS, BGP and the Kubernetes API. | | List of [ProtoPort](#protoport) | {::nomarkdown}<p><code>- protocol: udp<br>&nbsp;&nbsp;port: 53<br>- protocol: udp<br>&nbsp;&nbsp;port: 67<br>- protocol: tcp<br>&nbsp;&nbsp;port: 179<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2379<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2380<br>- protocol: tcp<br>&nbsp;&nbsp;port: 5473<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6443<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6666<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6667</code></p>{:/} |
| featureDetectOverride              | Is used to override the feature detection. Values are specified in a comma separated list with no spaces, example; "SNATFullyRandom=true,MASQFullyRandom=false,RestoreSupportsLock=". "true" or "false" will force the feature, empty or omitted values are auto-detected. | string | string | `""` |
| genericXDPEnabled                  | When enabled, Felix can fallback to the non-optimized `generic` XDP mode. This should only be used for testing since it doesn't improve performance over the non-XDP mode. | true,false | boolean | `false` |
| interfaceExclude                   | A comma-separated list of interface names that should be excluded when Felix is resolving host endpoints.  The default value ensures that Felix ignores Kubernetes' internal `kube-ipvs0` device. If you want to exclude multiple interface names using a single value, the list supports regular expressions. For regular expressions you must wrap the value with `/`. For example having values `/^kube/,veth1` will exclude all interfaces that begin with `kube` and also the interface `veth1`. | string | string | `kube-ipvs0` |
| interfacePrefix                    | The interface name prefix that identifies workload endpoints and so distinguishes them from host endpoint interfaces.  Note: in environments other than bare metal, the orchestrators configure this appropriately.  For example our Kubernetes and Docker integrations set the 'cali' value, and our OpenStack integration sets the 'tap' value. | string | string | `cali` |
| ipipEnabled                        | Optional, you shouldn't need to change this setting as Felix calculates if IPIP should be enabled based on the existing IP Pools. When set, this overrides whether Felix should configure an IPinIP interface on the host. When explicitly disabled in FelixConfiguration, Felix will not clean up addresses from the `tunl0` interface (use this if you need to add addresses to that interface and don't want to have them removed). | `true`, `false`, unset | optional boolean | unset |
| ipipMTU                            | The MTU to set on the tunnel device. Zero value means auto-detect. See [Configuring MTU]({{ site.baseurl }}/networking/mtu) | int | int | `0` |
| ipsetsRefreshInterval              | Period at which Felix re-checks the IP sets in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable IP sets refresh.  Note: the default for this value is lower than the other refresh intervals as a workaround for a [Linux kernel bug](https://github.com/projectcalico/felix/issues/1347){:target="_blank"} that was fixed in kernel version 4.11. If you are using v4.11 or greater you may want to set this to a higher value to reduce Felix CPU usage. | `5s`, `10s`, `1m` etc. | duration | `10s` |
| iptablesFilterAllowAction          | This parameter controls what happens to traffic that is accepted by a Felix policy chain in the iptables filter table (i.e. a normal policy chain). The default will immediately `Accept` the traffic. Use `Return` to send the traffic back up to the system chains for further processing.| Accept, Return |  string | `Accept` |
| iptablesBackend                    | This parameter controls which variant of iptables binary Felix uses.  If using Felix on a system that uses the netfilter-backed iptables binaries, set this to `NFT`. | Legacy, NFT | string | automatic detection |
| iptablesLockFilePath               | Location of the iptables lock file.  You may need to change this if the lock file is not in its standard location (for example if you have mapped it into Felix's container at a different path). | string | string | `/run/xtables.lock` |
| iptablesLockProbeInterval          | Time that Felix will wait between attempts to acquire the iptables lock if it is not available.  Lower values make Felix more responsive when the lock is contended, but use more CPU. | `5s`, `10s`, `1m` etc. | duration | `50ms` |
| iptablesLockTimeout                | Time that Felix will wait for the iptables lock, or 0, to disable.  To use this feature, Felix must share the iptables lock file with all other processes that also take the lock.  When running Felix inside a container, this requires the /run directory of the host to be mounted into the {{site.nodecontainer}} or calico/felix container. | `5s`, `10s`, `1m` etc. | duration | `0` (Disabled) |
| iptablesMangleAllowAction          | This parameter controls what happens to traffic that is accepted by a Felix policy chain in the iptables mangle table (i.e. a pre-DNAT policy chain). The default will immediately `Accept` the traffic. Use `Return` to send the traffic back up to the system chains for further processing. | Accept, Return |  string | `Accept` |
| iptablesMarkMask                   | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal number with at least 8 bits set, none of which clash with any other mark bits in use on the system. | netmask | netmask | `0xff000000` |
| iptablesNATOutgoingInterfaceFilter | This parameter can be used to limit the host interfaces on which Calico will apply SNAT to traffic leaving a Calico IPAM pool with "NAT outgoing" enabled.  This can be useful if you have a main data interface, where traffic should be SNATted and a secondary device (such as the docker bridge) which is local to the host and doesn't require SNAT.  This parameter uses the iptables interface matching syntax, which allows `+` as a wildcard.  Most users will not need to set this.  Example: if your data interfaces are eth0 and eth1 and you want to exclude the docker bridge, you could set this to `eth+` | string | string | `""` |
| iptablesPostWriteCheckInterval     | Period after Felix has done a write to the dataplane that it schedules an extra read back in order to check the write was not clobbered by another process.  This should only occur if another application on the system doesn't respect the iptables lock. | `5s`, `10s`, `1m` etc. | duration | `1s` |
| iptablesRefreshInterval            | Period at which Felix re-checks all iptables state to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable iptables refresh. | `5s`, `10s`, `1m` etc. | duration | `90s` |
| ipv6Support                        | IPv6 support for Felix | true, false | boolean | `true` |
| logFilePath                        | The full path to the Felix log. Set to `none` to disable file logging. | string | string | `/var/log/calico/felix.log` |
| logPrefix                          | The log prefix that Felix uses when rendering LOG rules. | string | string | `calico-packet` |
| logSeverityFile                    | The log severity above which logs are sent to the log file. | Same as `logSeveritySys` | string | `Info` |
| logSeverityScreen                  | The log severity above which logs are sent to the stdout. | Same as LogSeveritySys | string | `Info` |
| logSeveritySys                     | The log severity above which logs are sent to the syslog. Set to `none` for no logging to syslog. | Debug, Info, Warning, Error, Fatal | string | `Info` |
| logDebugFilenameRegex              | controls which source code files have their Debug log output included in the logs.  Only logs from files with names that match the given regular expression are included.  The filter only applies to Debug level logs. | regex | string | `""` |
| maxIpsetSize                       | Maximum size for the ipsets used by Felix. Should be set to a number that is greater than the maximum number of IP addresses that are ever expected in a selector. | int | int | `1048576` |
| metadataAddr                       | The IP address or domain name of the server that can answer VM queries for cloud-init metadata. In OpenStack, this corresponds to the machine running nova-api (or in Ubuntu, nova-api-metadata). A value of `none` (case insensitive) means that Felix should not set up any NAT rule for the metadata path.  | IPv4, hostname, none | string | `127.0.0.1` |
| metadataPort                       | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be changed. | int | int | `8775` |
| natOutgoingAddress                 | The source address to use for outgoing NAT. By default an iptables MASQUERADE rule determines the source address which will use the address on the host interface the traffic leaves on. | IPV4 | string | `""` |
| openstackRegion                    | The name of the region that a particular Felix belongs to. In a [multi-region Calico/OpenStack deployment]({{ site.baseurl }}/networking/openstack/multiple-regions), this must be configured somehow for each Felix (here in the datamodel, or in felix.cfg or the environment on each compute node), and must match the [calico] openstack_region value configured in neutron.conf on each node. | string of lower case alphanumeric characters or '-', starting and ending with an alphanumeric character | string | `""` |
| policySyncPathPrefix               | File system path where Felix notifies services of policy changes over Unix domain sockets. This is only required if you're configuring [application layer policy]({{ site.baseurl }}/security/app-layer-policy). Set to `""` to disable. | string | string | `""` |
| prometheusGoMetricsEnabled         | Set to `false` to disable Go runtime metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. | boolean | boolean | `true` |
| prometheusMetricsEnabled           | Set to `true` to enable the experimental Prometheus metrics server in Felix. | boolean | boolean | `false` |
| prometheusMetricsHost              | TCP network address that the Prometheus metrics server should bind to. | IPv4, IPv6, Hostname | string | `""` |
| prometheusMetricsPort              | TCP port that the Prometheus metrics server should bind to. | int | int | `9091` |
| prometheusProcessMetricsEnabled    | Set to `false` to disable process metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. | boolean | boolean | `true` |
| removeExternalRoutes               | Whether or not to remove device routes that have not been programmed by Felix. Disabling this will allow external applications to also add device routes. | bool | boolean | `true` |
| reportingInterval                  | Interval at which Felix reports its status into the datastore, or 0 to disable.  Must be non-zero in OpenStack deployments. | `5s`, `10s`, `1m` etc. | duration | `30s` |
| reportingTTL                       | Time-to-live setting for process-wide status reports. | `5s`, `10s`, `1m` etc. | duration | `90s` |
| routeRefreshInterval               | Period at which Felix re-checks the routes in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable route refresh. | `5s`, `10s`, `1m` etc. | duration | `90s` |
| routeTableRange                    | *deprecated in favor of `RouteTableRanges`* Calico programs additional Linux route tables for various purposes. `RouteTableRange` specifies the indices of the route tables that Calico should use. |  | [RouteTableRanges](#routetablerange) | `""` |
| routeTableRanges                    | Calico programs additional Linux route tables for various purposes. `RouteTableRanges` specifies a set of table index ranges that Calico should use. Deprecates `RouteTableRange`, overrides `RouteTableRange` |  | [RouteTableRanges](#routetableranges) | `[{"Min": 1, "Max": 250}]` |
| serviceLoopPrevention              | When [service IP advertisement is enabled]({{ site.baseurl }}/networking/advertise-service-ips), prevent routing loops to service IPs that are not in use, by dropping or rejecting packets that do not get DNAT'd by kube-proxy.  Unless set to "Disabled", in which case such routing loops continue to be allowed. | `Drop`, `Reject`, `Disabled` | string | `Drop` |
| workloadSourceSpoofing             | Controls whether pods can enable source IP address spoofing with the `cni.projectcalico.org/allowedSourcePrefixes` annotation. When set to `Any`, pods can use this annotation to send packets from any IP address. | `Any`, `Disabled` | string | `Disabled`
| sidecarAccelerationEnabled         | Enable experimental acceleration between application and proxy sidecar when using [application layer policy]({{ site.baseurl }}/security/app-layer-policy). [Default: `false`] | boolean | boolean | `false` |
| usageReportingEnabled              | Reports anonymous {{site.prodname}} version number and cluster size to projectcalico.org. Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of {{site.prodname}} being used. | boolean | boolean | `true` |
| usageReportingInitialDelay         | Minimum initial delay before first usage report. | `5s`, `10s`, `1m` etc. | duration | `300s` |
| usageReportingInterval             | The interval at which Felix does usage reports.  The default is 1 day.  | `5s`, `10s`, `1m` etc. | duration | `24h` |
| vxlanEnabled                       | Optional, you shouldn't need to change this setting as Felix calculates if VXLAN should be enabled based on the existing IP Pools. When set, this overrides whether Felix should create the VXLAN tunnel device for VXLAN networking. | `true`, `false`, unset | optional boolean | unset |
| vxlanMTU                           | MTU to use for the IPv4 VXLAN tunnel device. Zero value means auto-detect. Also controls NodePort MTU when eBPF enabled.                                                                                                              | int                    | int              | `0`   |
| vxlanMTUV6                         | MTU to use for the IPv6 VXLAN tunnel device. Zero value means auto-detect. Also controls NodePort MTU when eBPF enabled.                                                                                                              | int                    | int              | `0`   |
| vxlanPort                          | Port to use for VXLAN traffic. A value of `0` means "use the kernel default". | int | int | `4789` |
| vxlanVNI                           | Virtual network ID to use for VXLAN traffic. A value of `0` means "use the kernel default". | int | int | `4096` |
| allowVXLANPacketsFromWorkloads     | Set to `true` to allow VXLAN encapsulated traffic from workloads. | boolean | boolean | `false` |
| allowIPIPPacketsFromWorkloads      | Set to `true` to allow IPIP encapsulated traffic from workloads. | boolean | boolean | `false` |
| wireguardEnabled                   | Enable encryption on WireGuard supported nodes in cluster. When enabled, pod to pod traffic will be sent over encrypted tunnels between the nodes. | `true`, `false` | boolean | `false` |
| wireguardInterfaceName             | Name of the WireGuard interface created by Felix. If you change the name, and want to clean up the previously-configured interface names on each node, this is a manual process. | string | string | wireguard.cali |
| wireguardListeningPort             | Port used by WireGuard tunnels. Felix sets up WireGuard tunnel on each node specified by this port. Available for configuration only in the global FelixConfiguration resource; setting it per host, config-file or environment variable will not work. | 1-65535 | int | 51820 |
| wireguardMTU                       | MTU set on the WireGuard interface created by Felix. Zero value means auto-detect. See [Configuring MTU]({{ site.baseurl }}/networking/mtu). | int | int | 0 |
| wireguardRoutingRulePriority       | WireGuard routing rule priority value set up by Felix. If you change the default value, set it to a value most appropriate to routing rules for your nodes. | 1-32765 | int | 99 |
| wireguardHostEncryptionEnabled     | **Experimental**: Adds host-namespace workload IP's to WireGuard's list of peers. Should **not** be enabled when WireGuard is enabled on a cluster's control-plane node, as networking deadlock can occur. | true, false | boolean | false |
| wireguardKeepAlive                 | WireguardKeepAlive controls Wireguard PersistentKeepalive option. Set 0 to disable. [Default: 0] | `5s`, `10s`, `1m` etc. | duration | `0` |
| xdpRefreshInterval                 | Period at which Felix re-checks the XDP state in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable XDP refresh. | `5s`, `10s`, `1m` etc. | duration | `90s` |
| xdpEnabled                         | When `bpfEnabled` is `false`: enable XDP acceleration for host endpoint policies.  When `bpfEnabled` is `true`, XDP is automatically used for Calico policy where that makes sense, regardless of this setting.  [Default: `true`] | true,false | boolean | `true` |
| bpfEnabled                         | Enable eBPF dataplane mode.  eBPF mode has some limitations, see the [HOWTO guide]({{ site.baseurl }}/maintenance/ebpf/enabling-ebpf) for more details. | true, false | boolean | false |
| bpfDisableUnprivileged             | If true, Felix sets the kernel.unprivileged_bpf_disabled sysctl to disable unprivileged use of BPF.  This ensures that unprivileged users cannot access Calico's BPF maps and cannot insert their own BPF programs to interfere with the ones that {{site.prodname}} installs. | true, false | boolean | true |
| bpfLogLevel                        | In eBPF dataplane mode, the log level used by the BPF programs.  The logs are emitted to the BPF trace pipe, accessible with the command `tc exec bpf debug`. | Off,Info,Debug | string | Off |
| bpfDataIfacePattern                | In eBPF dataplane mode, controls which interfaces Felix should attach BPF programs to in order to catch traffic to/from the external network.  This needs to match the interfaces that Calico workload traffic flows over as well as any interfaces that handle incoming traffic to NodePorts and services from outside the cluster.  It should not match the workload interfaces (usually named cali...).. | regular expression | string | `^(en.*|eth.*|tunl0$)` |
| bpfConnectTimeLoadBalancingEnabled | In eBPF dataplane mode, controls whether Felix installs the connect-time load balancer.  In the current release, the connect-time load balancer is required for the host to reach kubernetes services. | true,false | boolean | true |
| bpfExternalServiceMode             | In eBPF dataplane mode, controls how traffic from outside the cluster to NodePorts and ClusterIPs is handled.  In Tunnel mode, packet is tunneled from the ingress host to the host with the backing pod and back again.  In DSR mode, traffic is tunneled to the host with the backing pod and then returned directly; this requires a network that allows direct return. | Tunnel,DSR | string | Tunnel |
| bpfKubeProxyIptablesCleanupEnabled | In eBPF dataplane mode, controls whether Felix will clean up the iptables rules created by the Kubernetes `kube-proxy`; should only be enabled if `kube-proxy` is not running. | true,false| boolean | true |
| bpfKubeProxyMinSyncPeriod          | In eBPF dataplane mode, controls the minimum time between dataplane updates for Felix's embedded `kube-proxy` implementation. | `5s`, `10s`, `1m` etc. | duration | `1s` |
| BPFKubeProxyEndpointSlicesEnabled  | In eBPF dataplane mode, controls whether Felix's embedded kube-proxy derives its services from Kubernetes' EndpointSlices resources. Using EndpointSlices is more efficient but it requires EndpointSlices support to be enabled at the Kubernetes API server. | true,false | boolean | false |
| bpfMapSizeConntrack | In eBPF dataplane mode, controls the size of the conntrack map. | int | int | 512000 |
| bpfMapSizeIPSets | In eBPF dataplane mode, controls the size of the ipsets map. | int | int | 1048576 |
| bpfMapSizeNATAffinity | In eBPF dataplane mode, controls the size of the NAT affinity map. | int | int | 65536 |
| bpfMapSizeNATFrontend | In eBPF dataplane mode, controls the size of the NAT front end map. | int | int | 65536 |
| bpfMapSizeNATBackend | In eBPF dataplane mode, controls the size of the NAT back end map. | int | int | 262144 |
| bpfMapSizeRoute | In eBPF dataplane mode, controls the size of the route map. | int | int | 262144 |
| routeSource                        | Where Felix gets is routing information from for VXLAN and the BPF dataplane. The CalicoIPAM setting is more efficient because it supports route aggregation, but it only works when Calico's IPAM or host-local IPAM is in use. Use the WorkloadIPs setting if you are using Calico's VXLAN or BPF dataplane and not using Calico IPAM or host-local IPAM. | CalicoIPAM,WorkloadIPs | string | `CalicoIPAM` |
| mtuIfacePattern                    | Pattern used to discover the host's interface for MTU auto-detection. | regex | string | `^((en|wl|ww|sl|ib)[opsx].*|(eth|wlan|wwan).*)` |

<br>

`genericXDPEnabled` and `xdpRefreshInterval` are only relevant when `bpfEnabled` is `false` and
`xdpEnabled` is `true`; in other words when XDP is being used to accelerate denial-of-service
prevention policies in the iptables dataplane.

When `bpfEnabled` is `true` the "xdp" settings all have no effect; in BPF mode the implementation of
policy is always accelerated, using the best available BPF technology.

#### ProtoPort

| Field    | Description          | Accepted Values                      | Schema |
|----------|----------------------|--------------------------------------|--------|
| port     | The exact port match | 0-65535                              | int    |
| protocol | The protocol match   | tcp, udp, sctp                       | string |
| net      | The CIDR match       | any valid CIDR (e.g. 192.168.0.0/16) | string |


#### RouteTableRange
The `RouteTableRange` option is now deprecated in favor of [RouteTableRanges](#routetableranges).

| Field    | Description          | Accepted Values   | Schema |
|----------|----------------------|-------------------|--------|
| min      | Minimum index to use | 1-250             | int    |
| max      | Maximum index to use | 1-250             | int    |

#### RouteTableRanges
`RouteTableRanges` is a list of `RouteTableRange` objects:

| Field    | Description          | Accepted Values | Schema |
|----------|----------------------|-----------------|--------|
| min      | Minimum index to use | 1 - 4294967295  | int    |
| max      | Maximum index to use | 1 - 4294967295  | int    |

Each item in the `RouteTableRanges` list designates a range of routing tables available to Calico. By default, Calico will use a single range of `1-250`.  If a range spans Linux's reserved table range (`253-255`) then those tables are automatically excluded from the list. It's possible that other table ranges may also be reserved by third-party systems unknown to Calico. In that case, multiple ranges can be defined to target tables below and above the sensitive ranges:
```sh
# target tables 65-99, and 256-1000, skipping 100-255
calicoctl patch felixconfig default --type=merge -p '{"spec":{"routeTableRanges": [{"Min": 65, "Max": 99}, {"Min": 256, "Max": 1000}] }}
```

*Note*, for performance reasons, the maximum total number of routing tables that Felix will accept is 65535 (or 2*16).

If both `RouteTableRanges` and `RouteTableRange` are set, `RouteTableRanges` takes precedence and `RouteTableRange` is ignored.

#### AWS IAM Role/Policy for source-destination-check configuration

Setting `awsSrcDstCheck` to `Disable` will automatically disable source-destination-check on EC2 instances in a cluster, provided necessary IAM roles and policies are set. One of the policies assigned to IAM role of cluster nodes must contain a statement similar to the following:

```
{
    "Effect": "Allow",
        "Action": [
            "ec2:DescribeInstances",
            "ec2:ModifyNetworkInterfaceAttribute"
        ],
    "Resource": "*"
}
```

If there are no policies attached to node roles containing the above statement, attach a new policy. For example, if a node role is `test-cluster-nodeinstance-role`, click on the IAM role in AWS console. In the `Permission policies` list, add a new inline policy with the above statement to the new policy JSON definition. For detailed information, see {% include open-new-window.html text='AWS documentation' url='https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_create.html?icmpid=docs_iam_console' %}.

For an EKS cluster, the necessary IAM role and policy is available by default. No further actions are needed.

### Supported operations

| Datastore type        | Create | Delete | Delete (Global `default`) | Update | Get/List | Notes |
|-----------------------|--------|--------|---------------------------|--------|----------|-------|
| etcdv3                | Yes    | Yes    | No                        | Yes    | Yes      |       |
| Kubernetes API server | Yes    | Yes    | No                        | Yes    | Yes      |       |
