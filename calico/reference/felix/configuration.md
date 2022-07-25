---
title: Configuring Felix
description: Configure Felix, the daemon that runs on every machine that provides endpoints.
canonical_url: '/reference/felix/configuration'
---

{% tabs %}
  <label:Operator,active:true>
<%

If you have installed Calico using the operator, you cannot modify the environment provided to felix directly. To configure felix, see the [FelixConfiguration](../resources/felixconfig) resource instead.

%>

  <label:Manifest>
<%

> **Note**: The following tables detail the configuration file and
> environment variable parameters. For `FelixConfiguration` resource settings,
> refer to [Felix Configuration Resource](../resources/felixconfig).
{: .alert .alert-info}

Configuration for Felix is read from one of four possible locations, in order, as follows.

1.  Environment variables.
2.  The Felix configuration file.
3.  Host-specific `FelixConfiguration` resources (`node.<nodename>`).
4.  The global `FelixConfiguration` resource (`default`).

The value of any configuration parameter is the value read from the
*first* location containing a value. For example, if an environment variable
contains a value, it takes top precedence.

If not set in any of these locations, most configuration parameters have
defaults, and it should be rare to have to explicitly set them.

The full list of parameters which can be set is as follows.

#### General configuration

| Configuration file parameter      | Environment variable                    | Description  | Schema |
| --------------------------------- | --------------------------------------- | -------------| ------ |
| `DataplaneWatchdogTimeout` | `FELIX_DATAPLANEWATCHDOGTIMEOUT` | Timeout before the main dataplane goroutine is determined to have hung and Felix will report non-live and non-ready. Can be increased if the liveness check incorrectly fails (for example if Felix is running slowly on a heavily loaded system). [Default: `90`] | int |
| `AwsSrcDstCheck`                  | `FELIX_AWSSRCDSTCHECK`                  | Set the {% include open-new-window.html text='source-destination-check' url='https://docs.aws.amazon.com/vpc/latest/userguide/VPC_NAT_Instance.html#EIP_Disable_SrcDestCheck' %} when using AWS EC2 instances. Check [IAM role and profile configuration]({{ site.baseurl }}/reference/resources/felixconfig#aws-iam-rolepolicy-for-source-destination-check-configuration) for setting the necessary permission for this setting to work. [Default: `DoNothing`] | `DoNothing`, `Disable`, `Enable` |
| `DatastoreType`                   | `FELIX_DATASTORETYPE`                   | The datastore that Felix should read endpoints and policy information from. [Default: `etcdv3`] | `etcdv3`, `kubernetes`|
| `DeviceRouteSourceAddress`        | `FELIX_DEVICEROUTESOURCEADDRESS`        | IPv4 address to use as the source hint on device routes programmed by Felix [Default: No source hint is set on programmed routes and for local traffic from host to workload the source address will be chosen by the kernel.] | `<IPv4-address>` |
| `DeviceRouteSourceAddressIPv6`    | `FELIX_DEVICEROUTESOURCEADDRESSIPV6`    | IPv6 address to use as the source hint on device routes programmed by Felix [Default: No source hint is set on programmed routes and for local traffic from host to workload the source address will be chosen by the kernel.] | `<IPv6-address>` |
| `DeviceRouteProtocol`             | `FELIX_DEVICEROUTEPROTOCOL`             | This defines the route protocol added to programmed device routes. [Default: `RTPROT_BOOT`] | int |
| `DisableConntrackInvalidCheck`    | `FELIX_DISABLECONNTRACKINVALIDCHECK`    | Disable the dropping of packets that aren't either a valid handshake or part of an established connection. [Default: `false`] | boolean |
| `EndpointReportingDelaySecs`      | `FELIX_ENDPOINTREPORTINGDELAYSECS`      | Set the endpoint reporting delay between status check intervals, in seconds. Only used if endpoint reporting is enabled. [Default: `1`] | int |
| `EndpointReportingEnabled`        | `FELIX_ENDPOINTREPORTINGENABLED`        | Enable the endpoint status reporter. [Default: `false`] | boolean |
| `ExternalNodesCIDRList`           | `FELIX_EXTERNALNODESCIDRLIST`           | Comma-delimited list of IPv4 or CIDR of external-non-calico-nodes from which IPIP traffic is accepted by calico-nodes. [Default: ""] | string |
| `FailsafeInboundHostPorts`        | `FELIX_FAILSAFEINBOUNDHOSTPORTS`        | Comma-delimited list of UDP/TCP/SCTP ports and CIDRs that Felix will allow incoming traffic to host endpoints on irrespective of the security policy. This is useful to avoid accidentally cutting off a host with incorrect configuration. For backwards compatibility, if the protocol is not specified, it defaults to "tcp". If a CIDR is not specified, it will allow traffic from all addresses. To disable all inbound host ports, use the value `none`. The default value allows ssh access, DHCP, BGP, etcd and the Kubernetes API. [Default: `tcp:22, udp:68, tcp:179, tcp:2379, tcp:2380, tcp:5473, tcp:6443, tcp:6666, tcp:6667`] | string |
| `FailsafeOutboundHostPorts`       | `FELIX_FAILSAFEOUTBOUNDHOSTPORTS`       | Comma-delimited list of UDP/TCP/SCTP ports and CIDRs that Felix will allow outgoing traffic from host endpoints to irrespective of the security policy. This is useful to avoid accidentally cutting off a host with incorrect configuration. For backwards compatibility, if the protocol is not specified, it defaults to "tcp". If a CIDR is not specified, it will allow traffic from all addresses. To disable all outbound host ports, use the value `none`. The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd as well as allowing DHCP, DNS, BGP and the Kubernetes API. [Default: `udp:53, udp:67, tcp:179, tcp:2379, tcp:2380, tcp:5473, tcp:6443, tcp:6666, tcp:6667`]  | string |
| `FelixHostname`                   | `FELIX_FELIXHOSTNAME`                   | The hostname Felix reports to the plugin. Should be used if the hostname Felix autodetects is incorrect or does not match what the plugin will expect. [Default: `socket.gethostname()`] | string |
| `HealthEnabled`                   | `FELIX_HEALTHENABLED`                   | When enabled, exposes felix health information via an http endpoint. | boolean |
| `HealthHost`                      | `FELIX_HEALTHHOST`                      | The address on which Felix will respond to health requests. [Default: `localhost`] | string |
| `HealthPort`                      | `FELIX_HEALTHPORT`                      | The port on which Felix will respond to health requests. [Default: `9099`] | int |
| `IpInIpEnabled`                   | `FELIX_IPINIPENABLED`                   | Optional, you shouldn't need to change this setting as Felix calculates if IPIP should be enabled based on the existing IP Pools. When set, this overrides whether Felix should configure an IPinIP interface on the host. When explicitly disabled in FelixConfiguration, Felix will not clean up addresses from the `tunl0` interface (use this if you need to add addresses to that interface and don't want to have them removed). [Default: unset] | optional boolean |
| `IpInIpMtu`                       | `FELIX_IPINIPMTU`                       | The MTU to set on the IPIP tunnel device. Zero value means auto-detect. See [Configuring MTU]({{ site.baseurl }}/networking/mtu) [Default: `0`] | int |
| `IPv4VXLANTunnelAddr`             |                                         | IP address of the IPv4 VXLAN tunnel. This is system configured and should not be updated manually. | string |
| `LogFilePath`                     | `FELIX_LOGFILEPATH`                     | The full path to the Felix log. Set to `none` to disable file logging. [Default: `/var/log/calico/felix.log`] | string |
| `LogSeverityFile`                 | `FELIX_LOGSEVERITYFILE`                 | The log severity above which logs are sent to the log file. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogSeverityScreen`               | `FELIX_LOGSEVERITYSCREEN`               | The log severity above which logs are sent to the stdout. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogSeveritySys`                  | `FELIX_LOGSEVERITYSYS`                  | The log severity above which logs are sent to the syslog. Set to `none` for no logging to syslog. [Default: `Info`] | `Debug`, `Info`, `Warning`, `Error`, `Fatal` |
| `LogDebugFilenameRegex`           | `FELIX_LOGDEBUGFILENAMEREGEX`           | Controls which source code files have their Debug log output included in the logs.  Only logs from files with names that match the given regular expression are included.  The filter only applies to Debug level logs. [Default: `""`] | regex |
| `PolicySyncPathPrefix`            | `FELIX_POLICYSYNCPATHPREFIX`            | File system path where Felix notifies services of policy changes over Unix domain sockets. This is only required if you're configuring [application layer policy](https://github.com/projectcalico/app-policy){:target="_blank"}. Set to `""` to disable. [Default: `""`] | string |
| `PrometheusGoMetricsEnabled`      | `FELIX_PROMETHEUSGOMETRICSENABLED`      | Set to `false` to disable Go runtime metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. [Default: `true`]  | boolean |
| `PrometheusMetricsEnabled`        | `FELIX_PROMETHEUSMETRICSENABLED`        | Set to `true` to enable the Prometheus metrics server in Felix. [Default: `false`] | boolean |
| `PrometheusMetricsHost`           | `FELIX_PROMETHEUSMETRICSHOST`           | TCP network address that the Prometheus metrics server should bind to. [Default: `""`] | string |
| `PrometheusMetricsPort`           | `FELIX_PROMETHEUSMETRICSPORT`           | TCP port that the Prometheus metrics server should bind to. [Default: `9091`] | int |
| `PrometheusProcessMetricsEnabled` | `FELIX_PROMETHEUSPROCESSMETRICSENABLED` | Set to `false` to disable process metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. [Default: `true`] | boolean |
| `PrometheusWireGuardMetricsEnabled` | `FELIX_PROMETHEUSWIREGUARDMETRICSENABLED` | Set to `false` to disable wireguard device metrics collection, which Felix does by default. [Default: `true`] | boolean |
| `RemoveExternalRoutes`            | `FELIX_REMOVEEXTERNALROUTES`            | Whether or not to remove device routes that have not been programmed by Felix. Disabling this will allow external applications to also add device routes. [Default: `true`] | bool |
| `ReportingIntervalSecs`           | `FELIX_REPORTINGINTERVALSECS`           | Interval at which Felix reports its status into the datastore or `0` to disable. Must be non-zero in OpenStack deployments. [Default: `30`] | int |
| `ReportingTTLSecs`                | `FELIX_REPORTINGTTLSECS`                | Time-to-live setting for process-wide status reports. [Default: `90`] | int |
| `RouteTableRange`                 | `FELIX_ROUTETABLERANGE`                 | *deprecated in favor of `RouteTableRanges`* Calico programs additional Linux route tables for various purposes. `RouteTableRange` specifies the indices of the route tables that Calico should use. [Default: `""`] | `<min>-<max>` |
| `RouteTableRanges`                 | `FELIX_ROUTETABLERANGES`                 | Calico programs additional Linux route tables for various purposes. `RouteTableRanges` specifies a set of table index ranges that Calico should use. Deprecates `RouteTableRange`, overrides `RouteTableRange`. [Default: `"1-250"`] | `<min>-<max>,<min>-<max>,...` |
| `RouteSyncDisabled`               | `FELIX_ROUTESYNCDISABLED`                 | Set to `true` to disable Calico programming routes to local workloads. [Default: `false`] | boolean |
| `SidecarAccelerationEnabled`      | `FELIX_SIDECARACCELERATIONENABLED`      | Enable experimental acceleration between application and proxy sidecar when using [application layer policy]({{site.baseurl}}/security/app-layer-policy). [Default: `false`] | boolean |
| `UsageReportingEnabled`           | `FELIX_USAGEREPORTINGENABLED`           | Reports anonymous {{site.prodname}} version number and cluster size to projectcalico.org. Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of {{site.prodname}} being used. [Default: `true`] | boolean |
| `UsageReportingInitialDelaySecs`  | `FELIX_USAGEREPORTINGINITIALDELAYSECS`  | Minimum delay before first usage report, in seconds. [Default: `300`] | int |
| `UsageReportingIntervalSecs`      | `FELIX_USAGEREPORTINGINTERVALSECS`      | Interval at which to make usage reports, in seconds. [Default: `86400`] | int |
| `VXLANEnabled`                    | `FELIX_VXLANENABLED`                    | Optional, you shouldn't need to change this setting as Felix calculates if VXLAN should be enabled based on the existing IP Pools. When set, this overrides whether Felix should create the VXLAN tunnel device for VXLAN networking. [Default: unset] | optional boolean |
| `VXLANMTU`                        | `FELIX_VXLANMTU`                        | The MTU to set on the IPv4 VXLAN tunnel device. Zero value means auto-detect. Also controls NodePort MTU when eBPF enabled. See [Configuring MTU]({{ site.baseurl }}/networking/mtu) [Default: `0`] | int |
| `VXLANMTUV6`                      | `FELIX_VXLANMTUV6`                        | The MTU to set on the IPv6 VXLAN tunnel device. Zero value means auto-detect. Also controls NodePort MTU when eBPF enabled. See [Configuring MTU]({{ site.baseurl }}/networking/mtu) [Default: `0`] | int |
| `VXLANPort`                       | `FELIX_VXLANPORT`                       | The UDP port to use for VXLAN. [Default: `4789`] | int |
| `VXLANTunnelMACAddr`              |                                         | MAC address of the IPv4 VXLAN tunnel. This is system configured and should not be updated manually. | string |
| `VXLANVNI`                        | `FELIX_VXLANVNI`                        | The virtual network ID to use for VXLAN. [Default: `4096`] | int |
| `AllowVXLANPacketsFromWorkloads`  | `FELIX_ALLOWVXLANPACKETSFROMWORKLOADS`  | Set to `true` to allow VXLAN encapsulated traffic from workloads. [Default: `false`] | boolean |
| `AllowIPIPPacketsFromWorkloads`   | `FELIX_ALLOWIPIPPACKETSFROMWORKLOADS`   | Set to `true` to allow IPIP encapsulated traffic from workloads. [Default: `false`] | boolean |
| `TyphaAddr`                       | `FELIX_TYPHAADDR`                       | IPv4 address at which Felix should connect to Typha. [Default: none] | string |
| `TyphaK8sServiceName`             | `FELIX_TYPHAK8SSERVICENAME`             | Name of the Typha Kubernetes service | string |
| `Ipv6Support`                     | `FELIX_IPV6SUPPORT`                     | Enable {{site.prodname}} networking and security for IPv6 traffic as well as for IPv4. | boolean |
| `RouteSource`                     | `FELIX_ROUTESOURCE`                     | Where Felix gets is routing information from for VXLAN and the BPF dataplane. The CalicoIPAM setting is more efficient because it supports route aggregation, but it only works when Calico's IPAM or host-local IPAM is in use. Use the WorkloadIPs setting if you are using Calico's VXLAN or BPF dataplane and not using Calico IPAM or host-local IPAM. [Default: "CalicoIPAM"] | 'CalicoIPAM', or 'WorkloadIPs' |
| `mtuIfacePattern`                 | `FELIX_MTUIFACEPATTERN`                 | Pattern used to discover the host's interface for MTU auto-detection. [Default: `^((en|wl|ww|sl|ib)[opsx].*|(eth|wlan|wwan).*)` | regex |
| `FeatureDetectOverride`           | `FELIX_FEATUREDETECTOVERRIDE`           | Is used to override the feature detection. Values are specified in a comma separated list with no spaces, example; "SNATFullyRandom=true,MASQFullyRandom=false,RestoreSupportsLock=true,IPIPDeviceIsL3=true. "true" or "false" will force the feature, empty or omitted values are auto-detected. [Default: `""`] | string |

#### etcd datastore configuration

| Configuration parameter | Environment variable  | Description | Schema |
| ----------------------- | --------------------- | ----------- | ------ |
| `EtcdCaFile`            | `FELIX_ETCDCAFILE`    | Path to the file containing the root certificate of the certificate authority (CA) that issued the etcd server certificate. Configures Felix to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing Felix to trust each of the CAs included. To disable authentication of the server by Felix, set the value to `none`. [Default: `/etc/ssl/certs/ca-certificates.crt`] | string |
| `EtcdCertFile`          | `FELIX_ETCDCERTFILE`  | Path to the file containing the client certificate issued to Felix. Enables Felix to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/felix/cert.pem` (optional) | string |
| `EtcdEndpoints`         | `FELIX_ETCDENDPOINTS` | Comma-delimited list of etcd endpoints to connect to. Example: `http://127.0.0.1:2379,http://127.0.0.2:2379`. | `<scheme>://<ip-or-fqdn>:<port>` |
| `EtcdKeyFile`           | `FELIX_ETCDKEYFILE`   | Path to the file containing the private key matching Felix's client certificate. Enables Felix to participate in mutual TLS authentication and identify itself to the etcd server. Example: `/etc/felix/key.pem` (optional) | string |


#### Kubernetes API datastore configuration

The Kubernetes API datastore driver reads its configuration from Kubernetes-provided environment variables.

#### iptables dataplane configuration

| Configuration parameter              | Environment variable                       | Description | Schema |
| ------------------------------------ | ------------------------------------------ | ----------- | ------ |
| `ChainInsertMode`                    | `FELIX_CHAININSERTMODE`                    | Controls whether Felix hooks the kernel's top-level iptables chains by inserting a rule at the top of the chain or by appending a rule at the bottom.  `Insert` is the safe default since it prevents {{site.prodname}}'s rules from being bypassed.  If you switch to `Append` mode, be sure that the other rules in the chains signal acceptance by falling through to the {{site.prodname}} rules, otherwise the {{site.prodname}} policy will be bypassed. [Default: `Insert`]  | `Insert`, `Append` |
| `DefaultEndpointToHostAction`        | `FELIX_DEFAULTENDPOINTTOHOSTACTION`        | This parameter controls what happens to traffic that goes from a workload endpoint to the host itself (after the traffic hits the endpoint egress policy). By default {{site.prodname}} blocks traffic from workload endpoints to the host itself with an iptables `Drop` action. If you want to allow some or all traffic from endpoint to host, set this parameter to `Return` or `Accept`.  Use `Return` if you have your own rules in the iptables "INPUT" chain; {{site.prodname}} will insert its rules at the top of that chain, then `Return` packets to the "INPUT" chain once it has completed processing workload endpoint egress policy. Use `Accept` to unconditionally accept packets from workloads after processing workload endpoint egress policy. [Default: `Drop`] | `Drop`, `Return`, `Accept` |
| `GenericXDPEnabled`                  | `FELIX_GENERICXDPENABLED`                  | When enabled, Felix can fallback to the non-optimized `generic` XDP mode. This should only be used for testing since it doesn't improve performance over the non-XDP mode. [Default: `false`] | boolean |
| `InterfaceExclude`                   | `FELIX_INTERFACEEXCLUDE`                   | A comma-separated list of interface names that should be excluded when Felix is resolving host endpoints.  The default value ensures that Felix ignores Kubernetes' internal `kube-ipvs0` device. If you want to exclude multiple interface names using a single value, the list supports regular expressions. For regular expressions you must wrap the value with `/`. For example having values `/^kube/,veth1` will exclude all interfaces that begin with `kube` and also the interface `veth1`. [Default: `kube-ipvs0`] | string |
| `IpsetsRefreshInterval`              | `FELIX_IPSETSREFRESHINTERVAL`              | Period, in seconds, at which Felix re-checks the IP sets in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable IP sets refresh.  Note: the default for this value is lower than the other refresh intervals as a workaround for a [Linux kernel bug](https://github.com/projectcalico/felix/issues/1347){:target="_blank"} that was fixed in kernel version 4.11. If you are using v4.11 or greater you may want to set this to, a higher value to reduce Felix CPU usage. [Default: `10`] | int |
| `IptablesBackend`                    | `FELIX_IPTABLESBACKEND`                    | This parameter controls which variant of iptables binary Felix uses. Set this to `Auto` for auto detection of the backend. If a specific backend is needed then use `NFT` for hosts using a netfilter backend or `Legacy` for others. [Default: `Auto`] | `Legacy`, `NFT`, `Auto` |
| `IptablesFilterAllowAction`          | `FELIX_IPTABLESFILTERALLOWACTION`          | This parameter controls what happens to traffic that is allowed by a Felix policy chain in the iptables filter table (i.e., a normal policy chain). The default will immediately `Accept` the traffic. Use `Return` to send the traffic back up to the system chains for further processing. [Default: `Accept`]  | `Accept`, `Return` |
| `IptablesLockFilePath`               | `FELIX_IPTABLESLOCKFILEPATH`               | *Deprecated:* For iptables versions prior to v1.6.2, location of the iptables lock file (later versions of iptables always use value "/run/xtables.lock").  You may need to change this if the lock file is not in its standard location (for example if you have mapped it into Felix's container at a different path). [Default: `/run/xtables.lock`]  | string |
| `IptablesLockProbeIntervalMillis`    | `FELIX_IPTABLESLOCKPROBEINTERVALMILLIS`    | Time, in milliseconds, that Felix will wait between attempts to acquire the iptables lock if it is not available.  Lower values make Felix more responsive when the lock is contended, but use more CPU. [Default: `50`]  | int |
| `IptablesLockTimeoutSecs`            | `FELIX_IPTABLESLOCKTIMEOUTSECS`            | Time, in seconds, that Felix will wait for the iptables lock.  Versions of iptables prior to v1.6.2 support disabling the iptables lock by setting this value to 0; v1.6.2 and above do not so Felix will default to 10s if a non-positive number is used. To use this feature, Felix must share the iptables lock file with all other processes that also take the lock.  When running Felix inside a container, this typically requires the file /run/xtables.lock on the host to be mounted into the `{{site.nodecontainer}}` or `calico/felix` container. [Default: `0` disabled for iptables <v1.6.2 or 10s for later versions] | int |
| `IptablesMangleAllowAction`          | `FELIX_IPTABLESMANGLEALLOWACTION`          | This parameter controls what happens to traffic that is allowed by a Felix policy chain in the iptables mangle table (i.e., a pre-DNAT policy chain). The default will immediately `Accept` the traffic. Use `Return` to send the traffic back up to the system chains for further processing. [Default: `Accept`]  | `Accept`, `Return` |
| `IptablesMarkMask`                   | `FELIX_IPTABLESMARKMASK`                   | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal number with at least 8 bits set, none of which clash with any other mark bits in use on the system.  When using {{site.prodname}} with Kubernetes' `kube-proxy` in IPVS mode, [we recommend allowing at least 16 bits](#ipvs-bits). [Default: `0xffff0000`] | netmask |
| `IptablesNATOutgoingInterfaceFilter` | `FELIX_IPTABLESNATOUTGOINGINTERFACEFILTER` | This parameter can be used to limit the host interfaces on which Calico will apply SNAT to traffic leaving a Calico IPAM pool with "NAT outgoing" enabled.  This can be useful if you have a main data interface, where traffic should be SNATted and a secondary device (such as the docker bridge) which is local to the host and doesn't require SNAT.  This parameter uses the iptables interface matching syntax, which allows `+` as a wildcard.  Most users will not need to set this.  Example: if your data interfaces are eth0 and eth1 and you want to exclude the docker bridge, you could set this to `eth+` | string |
| `IptablesPostWriteCheckIntervalSecs` | `FELIX_IPTABLESPOSTWRITECHECKINTERVALSECS` | Period, in seconds, after Felix has done a write to the dataplane that it schedules an extra read back in order to check the write was not clobbered by another process.  This should only occur if another application on the system doesn't respect the iptables lock. [Default: `1`] | int |
| `IptablesRefreshInterval`            | `FELIX_IPTABLESREFRESHINTERVAL`            | Period, in seconds, at which Felix re-checks all iptables state to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable iptables refresh. [Default: `90`] | int |
| `LogPrefix`                          | `FELIX_LOGPREFIX`                          | The log prefix that Felix uses when rendering LOG rules. [Default: `calico-packet`] | string |
| `MaxIpsetSize`                       | `FELIX_MAXIPSETSIZE`                       | Maximum size for the ipsets used by Felix. Should be set to a number that is greater than the maximum number of IP addresses that are ever expected in a selector. [Default: `1048576`] | int |
| `NATPortRange`                       | `FELIX_NATPORTRANGE`                       | Port range used by iptables for port mapping when doing outgoing NAT. (Example: `32768:65000`).  [Default: iptables maps source ports below 512 to other ports below 512: those between 512 and 1023 inclusive will be mapped to ports below 1024, and other ports will be mapped to 1024 or above. Where possible, no port alteration will occur.]  | string |
| `NATOutgoingAddress`                 | `FELIX_NATOUTGOINGADDRESS`                 | Source address used by iptables for an SNAT rule when doing outgoing NAT. [Default: an iptables `MASQUERADE` rule is used for outgoing NAT which will use the address on the interface traffic is leaving on.]  | `<IPv4-address>` |
| `NetlinkTimeoutSecs`                 | `FELIX_NETLINKTIMEOUTSECS`                 | Time, in seconds, that Felix will wait for netlink (i.e. routing table list/update) operations to complete before giving up and retrying. [Default: `10`] | float |
| `RouteRefreshInterval`               | `FELIX_ROUTEREFRESHINTERVAL`               | Period, in seconds, at which Felix re-checks the routes in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable route refresh. [Default: `90`] | int |
| `ServiceLoopPrevention`              | `FELIX_SERVICELOOPPREVENTION`              | When [service IP advertisement is enabled]({{ site.baseurl }}/networking/advertise-service-ips), prevent routing loops to service IPs that are not in use, by dropping or rejecting packets that do not get DNAT'd by kube-proxy.  Unless set to "Disabled", in which case such routing loops continue to be allowed. [Default: `Drop`] | `Drop`, `Reject`, `Disabled` |
| `WorkloadSourceSpoofing`             | `FELIX_WORKLOADSOURCESPOOFING`             | Controls whether pods can enable source IP address spoofing with the `cni.projectcalico.org/allowedSourcePrefixes` annotation. When set to `Any`, pods can use this annotation to send packets from any IP address. [Default: `Disabled`] | `Any`, `Disabled` |
| `XDPRefreshInterval`                 | `FELIX_XDPREFRESHINTERVAL`                 | Period, in seconds, at which Felix re-checks the XDP state in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable XDP refresh. [Default: `90`] | int |
| `XDPEnabled`                         | `FELIX_XDPENABLED`                         | Enable XDP acceleration for host endpoint policies. [Default: `true`] | boolean |

#### eBPF dataplane configuration

eBPF dataplane mode uses the Linux Kernel's eBPF virtual machine to implement networking and policy instead of iptables.  When BPFEnabled is set to `true`, Felix will:

* Require a v5.3 Linux kernel.
* Implement policy with eBPF programs instead of iptables.
* Activate its embedded implementation of `kube-proxy` to implement Kubernetes service load balancing.
* Disable support for IPv6.

See the [HOWTO guide]({{ site.baseurl }}/maintenance/ebpf/enabling-ebpf) for step-by step instructions to enable this feature.

| Configuration parameter / Environment variable                                        | Description | Schema | Default |
| ------------------------------------------------------------------------------------- | ----------- | ------ |---------|
| BPFEnabled                         / <br/> FELIX_BPFENABLED                           | Enable eBPF dataplane mode.  eBPF mode has a number of limitations, see the [HOWTO guide]({{ site.baseurl }}/maintenance/ebpf/enabling-ebpf). | true, false |  false |
| BPFDisableUnprivileged             / <br/> FELIX_BPFDISABLEUNPRIVILEGED               | If true, Felix sets the kernel.unprivileged_bpf_disabled sysctl to disable unprivileged use of BPF.  This ensures that unprivileged users cannot access Calico's BPF maps and cannot insert their own BPF programs to interfere with the ones that {{site.prodname}} installs. | true, false |  true |
| BPFLogLevel                        / <br/> FELIX_BPFLOGLEVEL                          | The log level used by the BPF programs.  The logs are emitted to the BPF trace pipe, accessible with the command `tc exec BPF debug`. | Off,Info,Debug | Off |
| BPFDataIfacePattern                / <br/> FELIX_BPFDATAIFACEPATTERN                  | Controls which interfaces Felix should attach BPF programs to in order to catch traffic to/from the external network.  This needs to match the interfaces that Calico workload traffic flows over as well as any interfaces that handle incoming traffic to NodePorts and services from outside the cluster.  It should not match the workload interfaces (usually named cali...).. | regular expression | `^(en[opsx].*|eth.*|tunl0$|wireguard.cali$)` |
| BPFConnectTimeLoadBalancingEnabled / <br/> FELIX_BPFCONNECTTIMELOADBALANCINGENABLED   | Controls whether Felix installs the connect-time load balancer.  In the current release, the connect-time load balancer is required for the host to reach kubernetes services. | true,false |  true |
| BPFExternalServiceMode             / <br/> FELIX_BPFEXTERNALSERVICEMODE               | Controls how traffic from outside the cluster to NodePorts and ClusterIPs is handled.  In Tunnel mode, packet is tunneled from the ingress host to the host with the backing pod and back again.  In DSR mode, traffic is tunneled to the host with the backing pod and then returned directly; this requires a network that allows direct return. | Tunnel,DSR |  Tunnel |
| BPFExtToServiceConnmark            / <br/> FELIX_BPFEXTTOSERVICECONNMARK              | Controls a 32bit mark that is set on connections from an external client to a local service. This mark allows us to control how packets of that connection are routed within the host and how is routing interpreted by RPF check. | int | 0 |
| BPFKubeProxyIptablesCleanupEnabled / <br/> FELIX_BPFKUBEPROXYIPTABLESCLEANUPENABLED   | Controls whether Felix will clean up the iptables rules created by the Kubernetes `kube-proxy`; should only be enabled if `kube-proxy` is not running. | true,false| true |
| BPFKubeProxyMinSyncPeriod          / <br/> FELIX_BPFKUBEPROXYMINSYNCPERIOD            | Controls the minimum time between dataplane updates for Felix's embedded `kube-proxy` implementation. | seconds | `1` |
| BPFKubeProxyEndpointSlicesEnabled  / <br/> FELIX_BPFKUBEPROXYENDPOINTSLICESENABLED    | Controls whether Felix's embedded kube-proxy derives its services from Kubernetes' EndpointSlices resources. Using EndpointSlices is more efficient but it requires EndpointSlices support to be enabled at the Kubernetes API server. | true,false | false |
| BPFMapSizeConntrack / <br/> FELIX_BPFMapSizeConntrack | Controls the size of the conntrack map. This map must be large enough to hold an entry for each active connection. Warning: changing the size of the conntrack map can cause disruption. | int | 512000 |
| BPFMapSizeNATFrontend / <br/> FELIX_BPFMapSizeNATFrontend | Controls the size of the NAT frontend map. FrontendMap should be large enough to hold an entry for each nodeport, external IP and each port in each service. | int | 65536 |
| BPFMapSizeNATBackend / <br/> FELIX_BPFMapSizeNATBackend | Controls the size of the NAT backend map. This is the total number of endpoints. This is mostly more than the size of the number of services. | int | 262144 |
| BPFMapSizeNATAffinity / <br/> FELIX_BPFMapSizeNATAffinity | Controls the size of the NAT affinity map. | int | 65536 |
| BPFMapSizeIPSets / <br/> FELIX_BPFMapSizeIPSets | Controls the size of the IPSets map. The IP sets map must be large enough to hold an entry for each endpoint matched by every selector in the source/destination matches in network policy.  Selectors such as "all()" can result in large numbers of entries (one entry per endpoint in that case). | int | 1048576 |
| BPFMapSizeRoute / <br/> FELIX_BPFMapSizeRoute | Controls the size of the route map. The routes map should be large enough to hold one entry per workload and a handful of entries per host (enough to cover its own IPs and tunnel IPs). | int | 262144 |
| BPFHostConntrackBypass / <br/> FELIX_BPFHostConntrackBypass | Controls whether to bypass Linux conntrack in BPF mode for workloads and services. | true,false | true |
| BPFPolicyDebugEnabled  / <br/> FELIX_BPFPOLICYDEBUGENABLED    | In eBPF dataplane mode, Felix records detailed information about the BPF policy programs, which can be examined with the calico-bpf command-line tool. | true, false |  true |

#### Kubernetes-specific configuration

| Configuration parameter | Environment variable       | Description  | Schema |
| ------------------------|----------------------------| ------------ | ------ |
| `KubeNodePortRanges`    | `FELIX_KUBENODEPORTRANGES` | A list of port ranges that Felix should treat as Kubernetes node ports.  Only when `kube-proxy` is configured to use IPVS mode:  Felix assumes that traffic arriving at the host of one of these ports will ultimately be forwarded instead of being terminated by a host process.  [Default: `30000:32767`] <a id="ipvs-portranges"></a>  | Comma-delimited list of `<min>:<max>` port ranges or single ports. |


> **Note**: <a id="ipvs-bits"></a> When using {{site.prodname}} with Kubernetes' `kube-proxy` in IPVS mode, {{site.prodname}} uses additional iptables mark bits to store an ID for each local {{site.prodname}} endpoint.
> For example, the default `IptablesMarkMask` value, `0xffff0000` gives {{site.prodname}} 16 bits, up to 6 of which are used for internal purposes, leaving 10 bits for endpoint IDs.
> 10 bits is enough for 1024 different values and {{site.prodname}} uses 2 of those for internal purposes, leaving enough for 1022 endpoints on the host.
{: .alert .alert-info}


#### OpenStack-specific configuration

| Configuration parameter | Environment variable    | Description  | Schema |
| ------------------------|------------------------ | ------------ | ------ |
| `MetadataAddr`          | `FELIX_METADATAADDR`    | The IP address or domain name of the server that can answer VM queries for cloud-init metadata. In OpenStack, this corresponds to the machine running nova-api (or in Ubuntu, nova-api-metadata). A value of `none`  (case insensitive) means that Felix should not set up any NAT rule for the metadata path. [Default: `127.0.0.1`]  | `<IPv4-address>`, `<hostname>`, `none` |
| `MetadataPort`          | `FELIX_METADATAPORT`    | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be changed [Default: `8775`].  | int |
| `OpenstackRegion`       | `FELIX_OPENSTACKREGION` | In a [multi-region deployment]({{ site.baseurl }}/networking/openstack/multiple-regions), the name of the region that this Felix is in. [Default: none].  | string\* |

\* If non-empty, the value specified for `OpenstackRegion` must be a
string of lower case alphanumeric characters or '-', starting and
ending with an alphanumeric character.

#### Bare metal specific configuration

| Configuration parameter | Environment variable    | Description | Schema |
| ----------------------- | ----------------------- | ----------- | ------ |
| `InterfacePrefix`       | `FELIX_INTERFACEPREFIX` | The interface name prefix that identifies workload endpoints and so distinguishes them from host endpoint interfaces. Accepts more than one interface name prefix in comma-delimited format, e.g., `tap,cali`. Note: in environments other than bare metal, the orchestrators configure this appropriately.  For example our Kubernetes and Docker integrations set the `cali` value, and our OpenStack integration sets the `tap` value. [Default: `cali`] | string |

#### Felix-Typha Configuration

| Configuration parameter | Environment variable        | Description | Schema |
| ----------------------- | --------------------------- | ----------- | ------ |
| `TyphaAddr`             | `FELIX_TYPHAADDR`           | Address of the Typha Server when running outside a K8S Cluster, in the format IP:PORT | string |
| `TyphaK8sServiceName`   | `FELIX_TYPHAK8SSERVICENAME` | Service Name of Typha Deployment when running inside a K8S Cluster | string |
| `TyphaK8sNamespace`     | `FELIX_TYPHAK8SNAMESPACE`   | Namespace of Typha Deployment when running inside a K8S Cluster. [Default: `kube-system`] | string |
| `TyphaReadTimeout`      | `FELIX_TYPHAREADTIMEOUT`    | Timeout of Felix when reading information from Typha, in seconds. [Default: 30] | int |
| `TyphaWriteTimeout`     | `FELIX_TYPHAWRITETIMEOUT`   | Timeout of Felix when writing information to Typha, in seconds. [Default: 30] | int |

#### Felix-Typha TLS configuration

| Configuration parameter | Environment variable   | Description | Schema |
| ----------------------- | ---------------------- | ----------- | ------ |
| `TyphaCAFile`           | `FELIX_TYPHACAFILE`    | Path to the file containing the root certificate of the CA that issued the Typha server certificate. Configures Felix to trust the CA that signed the root certificate. The file may contain multiple root certificates, causing Felix to trust each of the CAs included. Example: `/etc/felix/ca.pem` | string |
| `TyphaCertFile`         | `FELIX_TYPHACERTFILE`  | Path to the file containing the client certificate issued to Felix. Enables Felix to participate in mutual TLS authentication and identify itself to the Typha server. Example: `/etc/felix/cert.pem` | string |
| `TyphaCN`               | `FELIX_TYPHACN`        | If set, the `Common Name` that Typha's certificate must have. If you have enabled TLS on the communications from Felix to Typha, you must set a value here or in `TyphaURISAN`. You can set values in both, as well, such as to facilitate a migration from using one to the other. If either matches, the communication succeeds. [Default: none] | string |
| `TyphaKeyFile`          | `FELIX_TYPHAKEYFILE`   | Path to the file containing the private key matching the Felix client certificate. Enables Felix to participate in mutual TLS authentication and identify itself to the Typha server. Example: `/etc/felix/key.pem` (optional) | string |
| `TyphaURISAN`           | `FELIX_TYPHAURISAN`    | If set, a URI SAN that Typha's certificate must have. We recommend populating this with a [SPIFFE](https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md#2-spiffe-identity){:target="_blank"} string that identifies Typha. All Typha instances should use the same SPIFFE ID. If you have enabled TLS on the communications from Felix to Typha, you must set a value here or in `TyphaCN`. You can set values in both, as well, such as to facilitate a migration from using one to the other. If either matches, the communication succeeds. [Default: none] | string |

For more information on how to use and set these variables, refer to
[Connections from Felix to Typha (Kubernetes)](../../security/comms/crypto-auth#connections-from-felix-to-typha-kubernetes).

#### WireGuard configuration

| Configuration parameter | Environment variable   | Description | Schema |
| ----------------------- | ---------------------- | ----------- | ------ |
| wireguardEnabled                   | Enable encryption on WireGuard supported nodes in cluster. When enabled, pod to pod traffic will be sent over encrypted tunnels between the nodes. | `true`, `false` | boolean | `false` |
| wireguardInterfaceName             | Name of the WireGuard interface created by Felix. If you change the name, and want to clean up the previously-configured interface names on each node, this is a manual process. | string | string | wireguard.cali |
| wireguardListeningPort             | Port used by WireGuard tunnels. Felix sets up WireGuard tunnel on each node specified by this port. Available for configuration only in the global FelixConfiguration resource; setting it per host, config-file or environment variable will not work. | 1-65535 | int | 51820 |
| wireguardMTU                       | MTU set on the WireGuard interface created by Felix. Zero value means auto-detect. See [Configuring MTU]({{ site.baseurl }}/networking/mtu). | int | int | 0 |
| wireguardRoutingRulePriority       | WireGuard routing rule priority value set up by Felix. If you change the default value, set it to a value most appropriate to routing rules for your nodes. | 1-32765 | int | 99 |
| wireguardHostEncryptionEnabled     | **Experimental**: Adds host-namespace workload IP's to WireGuard's list of peers. Should **not** be enabled when WireGuard is enabled on a cluster's control-plane node, as networking deadlock can occur. | true, false | boolean | false |
| wireguardKeepAlive                 | WireguardKeepAlive controls Wireguard PersistentKeepalive option. Set 0 to disable. [Default: 0] | int | int | 25 |


For more information on encrypting in-cluster traffic with WireGuard, refer to
[Encrypt cluster pod traffic](../../security/encrypt-cluster-pod-traffic)

### Environment variables

The highest priority of configuration is that read from environment
variables. To set a configuration parameter via an environment variable,
set the environment variable formed by taking `FELIX_` and appending the
uppercase form of the variable name. For example, to set the etcd
address, set the environment variable `FELIX_ETCDADDR`. Other examples
include `FELIX_ETCDSCHEME`, `FELIX_ETCDKEYFILE`, `FELIX_ETCDCERTFILE`,
`FELIX_ETCDCAFILE`, `FELIX_FELIXHOSTNAME`, `FELIX_LOGFILEPATH` and
`FELIX_METADATAADDR`.

### Configuration file

On startup, Felix reads an ini-style configuration file. The path to
this file defaults to `/etc/calico/felix.cfg` but can be overridden
using the `-c` or `--config-file` options on the command line. If the
file exists, then it is read (ignoring section names) and all parameters
are set from it.

In OpenStack, we recommend putting all configuration into configuration
files, since the etcd database is transient (and may be recreated by the
OpenStack plugin in certain error cases). However, in a Docker
environment the use of environment variables or etcd is often more
convenient.

### Datastore

Felix also reads configuration parameters from the datastore.  It supports
a global setting and a per-host override.

1. Get the current felixconfig settings.

   ```bash
   calicoctl get felixconfig default -o yaml --export > felix.yaml
   ```

1. Modify logFilePath to your intended path, e.g. "/tmp/felix.log"

   ```bash
   vim felix.yaml
   ```
   > **Tip**: For a global change set name to "default".
   > For a node-specific change: set name to `node.<nodename>`, e.g. "node.{{site.prodname}}-node-1"
   {: .alert .alert-success}

1. Replace the current felixconfig settings

   ```bash
   calicoctl replace -f felix.yaml
   ```

For more information, see [Felix Configuration Resource](../resources/felixconfig).

%>

{% endtabs %}
