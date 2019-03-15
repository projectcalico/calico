---
title: Felix configuration
redirect_from: latest/reference/calicoctl/resources/felixconfig
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/calicoctl/resources/felixconfig'
---

A [Felix]({{site.baseurl}}/{{page.version}}/reference/architecture/#felix) configuration resource (`FelixConfiguration`) represents Felix configuration options for the cluster.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `felixconfiguration`, `felixconfig`, `felixconfigurations`, `felixconfigs`.

See [Configuring Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration) for more details.

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

- {{site.prodname}} automatically creates a resource named `default` containing the global default configuration settings for Felix. You can use [calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) to view and edit these settings
- The resources with the name `node.<nodename>` contain the node-specific overrides, and will be applied to the node `<nodename>`. When deleting a node the FelixConfiguration resource associated with the node will also be deleted.

#### Spec

| Field                              | Description                 | Accepted Values   | Schema | Default    |
|------------------------------------|-----------------------------|-------------------|--------|------------|
| chainInsertMode                    | Controls whether Felix hooks the kernel's top-level iptables chains by inserting a rule at the top of the chain or by appending a rule at the bottom. `Insert` is the safe default since it prevents {{site.prodname}}'s rules from being bypassed.  If you switch to `Append` mode, be sure that the other rules in the chains signal acceptance by falling through to the {{site.prodname}} rules, otherwise the {{site.prodname}} policy will be bypassed. | Insert, Append | string | `Insert` |
| defaultEndpointToHostAction        | This parameter controls what happens to traffic that goes from a workload endpoint to the host itself (after the traffic hits the endpoint egress policy).  By default {{site.prodname}} blocks traffic from workload endpoints to the host itself with an iptables "DROP" action. If you want to allow some or all traffic from endpoint to host, set this parameter to `Return` or `Accept`.  Use `Return` if you have your own rules in the iptables "INPUT" chain; {{site.prodname}} will insert its rules at the top of that chain, then `Return` packets to the "INPUT" chain once it has completed processing workload endpoint egress policy.  Use `Accept` to unconditionally accept packets from workloads after processing workload endpoint egress policy. | Drop, Return, Accept | string | `Drop` |
| failsafeInboundHostPorts           | UDP/TCP protocol/port pairs that Felix will allow incoming traffic to host endpoints on irrespective of the security policy. This is useful to avoid accidentally cutting off a host with incorrect configuration.  The default value allows SSH access, etcd, BGP and DHCP. |  | List of [ProtoPort](#protoport) | {::nomarkdown}<p><code> - protocol: tcp<br>&nbsp;&nbsp;port: 22<br>- protocol: udp<br>&nbsp;&nbsp;port: 68<br>- protocol: tcp<br>&nbsp;&nbsp;port: 179<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2379<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2380<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6666<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6667</code></p>{:/} |
| failsafeOutboundHostPorts          | UDP/TCP protocol/port pairs that Felix will allow outgoing traffic from host endpoints to irrespective of the security policy. This is useful to avoid accidentally cutting off a host with incorrect configuration.  The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd as well as allowing DHCP and DNS. | | List of [ProtoPort](#protoport) | {::nomarkdown}<p><code> - protocol: udp<br>&nbsp;&nbsp;port: 53<br>- protocol: udp<br>&nbsp;&nbsp;port: 67<br>- protocol: tcp<br>&nbsp;&nbsp;port: 179<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2379<br>- protocol: tcp<br>&nbsp;&nbsp;port: 2380<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6666<br>- protocol: tcp<br>&nbsp;&nbsp;port: 6667</code></p>{:/} |
| ignoreLooseRPF                     | Set to `true` to allow Felix to run on systems with loose reverse path forwarding (RPF). **Warning**: {{site.prodname}} relies on "strict" RPF checking being enabled to prevent workloads, such as VMs and privileged containers, from spoofing their IP addresses and impersonating other workloads (or hosts).  Only enable this flag if you need to run with "loose" RPF and you either trust your workloads or have another mechanism in place to prevent spoofing.  | boolean | boolean | `false` |
| interfaceExclude                   | A comma-separated list of interface names that should be excluded when Felix is resolving host endpoints.  The default value ensures that Felix ignores Kubernetes' internal `kube-ipvs0` device. | string | string | `kube-ipvs0` |
| interfacePrefix                    | The interface name prefix that identifies workload endpoints and so distinguishes them from host endpoint interfaces.  Note: in environments other than bare metal, the orchestrators configure this appropriately.  For example our Kubernetes and Docker integrations set the 'cali' value, and our OpenStack integration sets the 'tap' value. | string | string | `cali` |
| ipipEnabled                        | Whether Felix should configure an IPinIP interface on the host. Set automatically to `true` by `{{site.nodecontainer}}` or `calicoctl` when you create an IPIP-enabled pool. | boolean | `false` |
| ipipMTU                            | The MTU to set on the tunnel device. See [Configuring MTU]({{site.baseurl}}/{{page.version}}/networking/mtu) | int | int | `1440` |
| ipsetsRefreshInterval              | Period, in seconds, at which Felix re-checks the IP sets in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable IP sets refresh.  Note: the default for this value is lower than the other refresh intervals as a workaround for a [Linux kernel bug](https://github.com/projectcalico/felix/issues/1347) that was fixed in kernel version 4.11. If you are using v4.11 or greater you may want to set this to a higher value to reduce Felix CPU usage. | int | int | `10` |
| iptablesFilterAllowAction          | This parameter controls what happens to traffic that is accepted by a Felix policy chain in the iptables filter table (i.e. a normal policy chain). The default will immediately `Accept` the traffic. Use `Return` to send the traffic back up to the system chains for further processing.| Accept, Return |  string | `Accept` |
| iptablesLockFilePath               | Location of the iptables lock file.  You may need to change this if the lock file is not in its standard location (for example if you have mapped it into Felix's container at a different path). | string | string | `/run/xtables.lock` |
| iptablesLockProbeIntervalMillis    | Time, in milliseconds, that Felix will wait between attempts to acquire the iptables lock if it is not available.  Lower values make Felix more responsive when the lock is contended, but use more CPU. | int | int | `50` |
| iptablesLockTimeoutSecs            | Time, in seconds, that Felix will wait for the iptables lock, or 0, to disable.  To use this feature, Felix must share the iptables lock file with all other processes that also take the lock.  When running Felix inside a container, this requires the /run directory of the host to be mounted into the {{site.nodecontainer}} or calico/felix container. | int | int | `0` (Disabled) |
| iptablesMangleAllowAction          | This parameter controls what happens to traffic that is accepted by a Felix policy chain in the iptables mangle table (i.e. a pre-DNAT policy chain). The default will immediately `Accept` the traffic. Use `Return` to send the traffic back up to the system chains for further processing. | Accept, Return |  string | `Accept` |
| iptablesMarkMask                   | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal number with at least 8 bits set, none of which clash with any other mark bits in use on the system. | netmask | netmask | `0xff000000` |
| iptablesPostWriteCheckIntervalSecs | Period, in seconds, after Felix has done a write to the dataplane that it schedules an extra read back in order to check the write was not clobbered by another process.  This should only occur if another application on the system doesn't respect the iptables lock. | int | int | `1` |
| iptablesRefreshIntervalSecs        | Period, in seconds, at which Felix re-checks all iptables state to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable iptables refresh. | int | int | `90` |
| ipv6Support                        | IPv6 support for Felix | true, false | boolean | `true` |
| logFilePath                        | The full path to the Felix log. Set to `""` to disable file logging. | string | string | `/var/log/calico/felix.log` |
| logPrefix                          | The log prefix that Felix uses when rendering LOG rules. | string | string | `calico-packet` |
| logSeverityFile                    | The log severity above which logs are sent to the log file. | Same as `logSeveritySys` | string | `Info` |
| logSeverityScreen                  | The log severity above which logs are sent to the stdout. | Same as LogSeveritySys | string | `Info` |
| logSeveritySys                     | The log severity above which logs are sent to the syslog. Set to `""` for no logging to syslog. | Debug, Info, Warning, Error, Fatal | string | `Info` |
| maxIpsetSize                       | Maximum size for the ipsets used by Felix to implement tags. Should be set to a number that is greater than the maximum number of IP addresses that are ever expected in a tag. | int | int | `1048576` |
| metadataAddr                       | The IP address or domain name of the server that can answer VM queries for cloud-init metadata. In OpenStack, this corresponds to the machine running nova-api (or in Ubuntu, nova-api-metadata). A value of `none` (case insensitive) means that Felix should not set up any NAT rule for the metadata path.  | IPv4, hostname, none | string | `127.0.0.1` |
| metadataPort                       | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be changed. | int | int | `8775` |
| openstackRegion                    | The name of the region that a particular Felix belongs to. In a [multi-region Calico/OpenStack deployment]({{site.baseurl}}/{{page.version}}/networking/openstack/multiple-regions), this must be configured somehow for each Felix (here in the datamodel, or in felix.cfg or the environment on each compute node), and must match the [calico] openstack_region value configured in neutron.conf on each node. | string of lower case alphanumeric characters or '-', starting and ending with an alphanumeric character | string | `""` |
| policySyncPathPrefix               | File system path where Felix notifies services of policy changes over Unix domain sockets. This is only required if you're configuring [application layer policy](https://github.com/projectcalico/app-policy). Set to `""` to disable. | string | string | `""` |
| prometheusGoMetricsEnabled         | Set to `false` to disable Go runtime metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. | boolean | boolean | `true` |
| prometheusMetricsEnabled           | Set to `true` to enable the experimental Prometheus metrics server in Felix. | boolean | boolean | `false` |
| prometheusMetricsPort              | Experimental: TCP port that the Prometheus metrics server should bind to. | int | int | `9091` |
| prometheusProcessMetricsEnabled    | Set to `false` to disable process metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. | boolean | boolean | `true` |
| reportingIntervalSecs              | Interval at which Felix reports its status into the datastore or 0 to disable.  Must be non-zero in OpenStack deployments. | int | int | `30` |
| reportingTTLSecs                   | Time-to-live setting for process-wide status reports. | int | int | `90` |
| routeRefreshIntervalSecs           | Period, in seconds, at which Felix re-checks the routes in the dataplane to ensure that no other process has accidentally broken {{site.prodname}}'s rules. Set to 0 to disable route refresh. | int | int | `90` |
| usageReportingEnabled              | Reports anonymous {{site.prodname}} version number and cluster size to projectcalico.org. Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of {{site.prodname}} being used. | boolean | boolean | `true` |
| usageReportingInitialDelaySecs     | Minimum initial delay before first usage report, in seconds. | int | int | `300` |
| usageReportingIntervalSecs         | The interval at which Felix does usage reports, in seconds.  The default is 1 day.  | int | int | `86400` |


#### ProtoPort

| Field    | Description          | Accepted Values   | Schema |
|----------|----------------------|-------------------|--------|
| port     | The exact port match | 0-65535           | int    |
| protocol | The protocol match   | tcp, udp          | string |

### Supported operations

| Datastore type        | Create  | Delete | Delete (Global `default`)  |  Update  | Get/List | Notes
|-----------------------|---------|--------|----------------------------|----------|----------|------
| etcdv3                | Yes     | Yes    | No                         | Yes      | Yes      |
| Kubernetes API server | Yes     | Yes    | No                         | Yes      | Yes      |
