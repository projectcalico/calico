---
title: Felix Configuration Resource (FelixConfiguration)
no_canonical: true
---

A [Felix]({{site.baseurl}}/{{page.version}}/reference/architecture/#felix) configuration resource (`FelixConfiguration`) represents Felix configuration options for the cluster.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `felixconfiguration`, `felixconfig`, `felixconfigurations`, `felixconfigs`.

See [Configuring Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration) for more details.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v2
kind: FelixConfiguration
metadata:
  name: default
spec:
  ipv6Support: false
  ipInIpMtu: 1400
  chainInsertMode: Append
```

### Felix Configuration Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Required. | Alphanumeric string with optional `.`, `_`, `-`, or `/` | string |

- Calico automatically creates a resource named `default` containing the global default configuration settings for Felix. You can use [calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) to view and edit these settings
- The resources with the name `node.<nodename>` contain the node-specific overrides, and will be applied to the node `<nodename>`. When deleting a node the FelixConfiguration resource associated with the node will also be deleted.

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| ipv6Support | IPv6 support for Felix | true, false | boolean | `false` |
| logFilePath | The full path to the Felix log. Set to `none` to disable file logging. | string | string | `/var/log/calico/felix.log` |
| logSeveritySys | The log severity above which logs are sent to the syslog. Set to `NONE` for no logging to syslog. | DEBUG, INFO, WARNING, ERROR, CRITICAL, or NONE (case-insensitive) | string | `INFO` |
| logSeverityFile| The log severity above which logs are sent to the log file. | Same as `logSeveritySys` | string | `INFO` |
| logSeverityScreen | The log severity above which logs are sent to the stdout. | Same as LogSeveritySys | string | `INFO` |
| prometheusMetricsEnabled | Set to `true` to enable the experimental Prometheus metrics server in Felix. | boolean | boolean | `false` |
| prometheusMetricsPort | Experimental: TCP port that the Prometheus metrics server should bind to. | int | int | `9091` |
| prometheusGoMetricsEnabled | Set to `false` to disable Go runtime metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. | boolean | boolean | `true` |
| prometheusProcessMetricsEnabled | Set to `false` to disable process metrics collection, which the Prometheus client does by default. This reduces the number of metrics reported, reducing Prometheus load. | boolean | boolean | `true` |
| usageReportingEnabled | Reports anonymous Calico version number and cluster size to projectcalico.org. Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of Calico being used. | boolean | boolean | `true` |
| failsafeInboundHostPorts | Comma-delimited list of UDP/TCP ports that Felix will allow incoming traffic to host endpoints on irrespective of the security policy.  This is useful to avoid accidently cutting off a host with incorrect configuration.  Each port should be specified as `tcp:<port-number>` or `udp:<port-number>`.  For back-compatibility, if the protocol is not specified, it defaults to "tcp".  To disable all inbound host ports, use the value `none`.  The default value allows ssh access and DHCP. | string | string | `tcp:22, udp:68` |
| failsafeOutboundHostPorts | Comma-delimited list of UDP/TCP ports that Felix will allow outgoing traffic from host endpoints to irrespective of the security policy. This is useful to avoid accidently cutting off a host with incorrect configuration.  Each port should be specified as `tcp:<port-number>` or `udp:<port-number>`.  For back-compatibility, if the protocol is not specified, it defaults to "tcp".  To disable all outbound host ports, use the value `none`.  The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd as well as allowing DHCP and DNS. | string | string | `tcp:2379, tcp:2380, tcp:4001, tcp:7001, udp:53, udp:67` |
| reportingIntervalSecs | Interval at which Felix reports its status into the datastore or 0 to disable.  | int | int | `30` |
| reportingTTLSecs | Time-to-live setting for process-wide status reports. | int | int | `90` |
| ipInIpMtu | The MTU to set on the tunnel device. See [Configuring MTU]({{site.baseurl}}/{{page.version}}/usage/configuration/mtu) | int | int | `1440` |
| defaultEndpointToHostAction | This parameter controls what happens to traffic that goes from a workload endpoint to the host itself (after the traffic hits the endpoint egress policy).  By default Calico blocks traffic from workload endpoints to the host itself with an iptables "DROP" action. If you want to allow some or all traffic from endpoint to host, set this parameter to `RETURN` or `ACCEPT`.  Use `RETURN` if you have your own rules in the iptables "INPUT" chain; Calico will insert its rules at the top of that chain, then "RETURN" packets to the "INPUT" chain once it has completed processing workload endpoint egress policy.  Use `ACCEPT` to unconditionally accept packets from workloads after processing workload endpoint egress policy. | DROP, RETURN, ACCEPT (case insensitive) | string | `DROP` |
| iptablesFilterAllowAction | This parameter controls what happens to traffic that is accepted by a Felix policy chain in the iptables filter table (i.e. a normal policy chain). The default will immediately ACCEPT the traffic. Use RETURN to send the traffic back up to the system chains for further processing.| ACCEPT, RETURN (case insensitive) |  string | `ACCEPT` |
| iptablesMangleAllowAction | This parameter controls what happens to traffic that is accepted by a Felix policy chain in the iptables mangle table (i.e. a pre-DNAT policy chain). The default will immediately ACCEPT the traffic. Use RETURN to send the traffic back up to the system chains for further processing. | ACCEPT, RETURN (case insensitive) |  string | `ACCEPT` |
| iptablesMarkMask | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal number with at least 8 bits set, none of which clash with any other mark bits in use on the system. | netmask | netmask | `0xff000000` |
| iptablesRefreshInterval | Period, in seconds, at which Felix re-checks all iptables state to ensure that no other process has accidentally broken Calico's rules. Set to 0 to disable iptables refresh. | int | int | `90` |
| iptablesPostWriteCheckIntervalSecs | Period, in seconds, after Felix has done a write to the dataplane that it schedules an extra read back in order to check the write was not clobbered by another process.  This should only occur if another application on the system doesn't respect the iptables lock. | int | int | `1` |
| routeRefreshInterval | Period, in seconds, at which Felix re-checks the routes in the dataplane to ensure that no other process has accidentally broken Calico's rules. Set to 0 to disable route refresh. | int | int | `90` |
| ipsetsRefreshInterval | Period, in seconds, at which Felix re-checks the IP sets in the dataplane to ensure that no other process has accidentally broken Calico's rules. Set to 0 to disable IP sets refresh.  Note: the default for this value is lower than the other refresh intervals as a workaround for a [Linux kernel bug](https://github.com/projectcalico/felix/issues/1347) that was fixed in kernel version 4.11. If you are using v4.11 or greater you may want to set this to, a higher value to reduce Felix CPU usage. | int | int | `10` |
| maxIpsetSize | Maximum size for the ipsets used by Felix to implement tags. Should be set to a number that is greater than the maximum number of IP addresses that are ever expected in a tag. | int | int | `1048576` |
| ChainInsertMode | Controls whether Felix hooks the kernel's top-level iptables chains by inserting a rule at the top of the chain or by appending a rule at the bottom.  `insert` is the safe default since it prevents Calico's rules from being bypassed.  If you switch to `append` mode, be sure that the other rules in the chains signal acceptance by falling through to the Calico rules, otherwise the Calico policy will be bypassed. | INSERT, APPEND (case insensitive) | string | `insert` |
| logPrefix | The log prefix that Felix uses when rendering LOG rules. | string | string | `calico-packet` |
| iptablesLockTimeoutSecs | Time, in seconds, that Felix will wait for the iptables lock, or 0, to disable.  To use this feature, Felix must share the iptables lock file with all other processes that also take the lock.  When running Felix inside a container, this requires the /run directory of the host to be mounted into the calico/node or calico/felix container. | int | int | `0` (Disabled) |
| iptablesLockFilePath | Location of the iptables lock file.  You may need to change this if the lock file is not in its standard location (for example if you have mapped it into Felix's container at a different path). | string | string | `/run/xtables.lock` |
| iptablesLockProbeIntervalMillis | Time, in milliseconds, that Felix will wait between attempts to acquire the iptables lock if it is not available.  Lower values make Felix more responsive when the lock is contended, but use more CPU. | int | int | `50` |
| metadataAddr | The IP address or domain name of the server that can answer VM queries for cloud-init metadata. A value of `none`  (case insensitive) means that Felix should not set up any NAT rule for the metadata path.  | IPv4, hostname, none | string | `127.0.0.1` |
| metadataPort | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be changed. | int | int | `8775` |
| interfacePrefix | The interface name prefix that identifies workload endpoints and so distinguishes them from host endpoint interfaces.  Note: in environments other than bare metal, the orchestrators configure this appropriately.  For example our Kubernetes and Docker integrations set the 'cali' value. | string | string | `cali` |

### Supported operations

| Datastore type        | Create    | Delete    | Delete (Global `default`)  |  Update  | Get/List | Notes
|-----------------------|------------|-----------|--------|----------|----------|------
| etcdv3                | Yes       | Yes    | No     | Yes      | Yes      |
| Kubernetes API server | Yes        | Yes   | No     | Yes      | Yes      |