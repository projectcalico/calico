---
title: Configuring Felix
canonical_url: 'https://docs.projectcalico.org/v3.5/reference/felix/configuration'
---

Configuration for Felix is read from one of four possible locations, in
order, as follows.

1.  Environment variables.
2.  The Felix configuration file.
3.  Host specific configuration in etcd.
4.  Global configuration in etcd.

The value of any configuration parameter is the value read from the
*first* location containing a value. If not set in any of these
locations, most configuration parameters have defaults, and it should be
rare to have to explicitly set them.

The full list of parameters which can be set is as follows.

#### Global configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| DatastoreType                           | FELIX_DATASTORETYPE                     | etcdv2                               | One of "etcdv2" or "kubernetes".  The datastore that Felix should read endpoints and policy information from.  |
| FelixHostname                           | FELIX_FELIXHOSTNAME                     | socket.gethostname()                 | The hostname Felix reports to the plugin. Should be used if the hostname Felix autodetects is incorrect or does not match what the plugin will expect.  |
| LogFilePath                             | FELIX_LOGFILEPATH                       | /var/log/calico/felix.log            | The full path to the felix log. Set to "none" to disable file logging.  |
| LogSeveritySys                          | FELIX_LOGSEVERITYSYS                    | INFO                                 | The log severity above which logs are sent to the syslog. Valid values are DEBUG, INFO, WARNING, ERROR and CRITICAL, or NONE for no logging to syslog (all values case insensitive).  |
| LogSeverityFile                         | FELIX_LOGSEVERITYFILE                   | INFO                                 | The log severity above which logs are sent to the log file. Valid values as for LogSeveritySys.  |
| LogSeverityScreen                       | FELIX_LOGSEVERITYSCREEN                 | INFO                                 | The log severity above which logs are sent to the stdout. Valid values as for LogSeveritySys.  |
| PrometheusMetricsEnabled                | FELIX_PROMETHEUSMETRICSENABLED          | "false"                              | Set to "true" to enable the experimental Prometheus metrics server in Felix.  |
| PrometheusMetricsPort                   | FELIX_PROMETHEUSMETRICSPORT             | 9091                                 | Experimental: TCP port that the Prometheus metrics server should bind to.  |
| UsageReportingEnabled                   | FELIX_USAGEREPORTINGENABLED             | "true"                               | Reports anonymous Calico version number and cluster size to projectcalico.org.  Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of Calico being used.  |
| FailsafeInboundHostPorts                | FELIX_FAILSAFEINBOUNDHOSTPORTS          | 22                                   | Comma-delimited list of TCP ports that Felix will allow incoming traffic to host endpoints on irrespective of the security policy. To disable all inbound host ports, use the value "none". This is useful to avoid accidently cutting off a host with incorrect configuration. The default value allows ssh access.  |
| FailsafeOutboundHostPorts               | FELIX_FAILSAFEOUTBOUNDHOSTPORTS         | 2379,2380,4001,7001                  | Comma-delimited list of TCP ports that Felix will allow outgoing from traffic from host endpoints to irrespective of the security policy. To disable all outbound host ports, use the value "none". This is useful to avoid accidently cutting off a host with incorrect configuration. The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd.  |
| ReportingIntervalSecs                   | FELIX_REPORTINGINTERVALSECS             | 30                                   | Interval at which Felix reports its status into the datastore or 0 to disable.  Must be non-zero in OpenStack deployments.  |
| ReportingTTLSecs                        | FELIX_REPORTINGTTLSECS                  | 90                                   | Time-to-live setting for process-wide status reports. |
| IpInIpMtu                               | FELIX_IPINIPMTU                         | 1440                                 | The MTU to set on the tunnel device. See [Configuring MTU]({{site.baseurl}}/{{page.version}}/usage/configuration/mtu) |

#### etcdv2 datastore configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| EtcdEndpoints                           | FELIX_ETCDENDPOINTS                     | "EtcdScheme://EtcdAddr"              | Comma-delimited list of etcd endpoints to connect to; for example "http://etcd1:2379,http://etcd2:2379".  |
| _Deprecated_ EtcdAddr                   | FELIX_ETCDADDR                          | 127.0.0.1:2379                       | The location (IP / hostname and port) of the etcd node or proxy that Felix should connect to.  |
| _Deprecated_ EtcdScheme                 | FELIX_ETCDSCHEME                        | http                                 | The protocol type (http or https) of the etcd node or proxy that Felix connects to.  |
| EtcdKeyFile                             | FELIX_ETCDKEYFILE                       | None                                 | The full path to the etcd private key file, as described in usingtlswithetcd  |
| EtcdCertFile                            | FELIX_ETCDCERTFILE                      | None                                 | The full path to the etcd certificate file, as described in usingtlswithetcd  |
| EtcdCaFile                              | FELIX_ETCDCAFILE                        | "/etc/ssl/certs/ca-certificates.crt" | The full path to the etcd Certificate Authority certificate file, as described in usingtlswithetcd. The default value is the standard location of the system trust store. To disable authentication of the server by Felix, set the value to "none".  |

#### Kubernetes datastore configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| N/A                                     | N/A                                     |                                      | The Kubernetes datastore driver reads its configuration from Kubernetes-provided environment variables.  |


#### iptables dataplane configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| DefaultEndpointToHostAction             | FELIX_DEFAULTENDPOINTTOHOSTACTION       | DROP                                 | This parameter controls what happens to traffic that goes from a workload endpoint to the host itself (after the traffic hits the endpoint egress policy).  By default Calico blocks traffic from workload endpoints to the host itself with an iptables "DROP" action. If you want to allow some or all traffic from endpoint to host, set this parameter to "RETURN" or "ACCEPT".  Use "RETURN" if you have your own rules in the iptables "INPUT" chain; Calico will insert its rules at the top of that chain, then "RETURN" packets to the "INPUT" chain once it has completed processing workload endpoint egress policy.  Use "ACCEPT" to unconditionally accept packets from workloads after processing workload endpoint egress policy.  |
| IptablesMarkMask                        | FELIX_IPTABLESMARKMASK                  | 0xff000000                           | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal number with at least 8 bits set, none of which clash with any other mark bits in use on the system.  |
| IptablesRefreshInterval                 | FELIX_IPTABLESREFRESHINTERVAL           | 60                                   | Period, in seconds, at which felix re-applies all iptables state to ensure that no other process has accidentally broken Calico's rules. Set to 0 to disable iptables refresh.  |
| ChainInsertMode                         | FELIX_CHAININSERTMODE                   | insert                               | One of "insert" or "append".  Controls whether Felix hooks the kernel's top-level iptables chains by inserting a rule at the top of the chain or by appending a rule at the bottom.  "insert" is the safe default since it prevents Calico's rules from being bypassed.  If you switch to "append" mode, be sure that the other rules in the chains signal acceptance by falling through to the Calico rules, otherwise the Calico policy will be bypassed.  |
| LogPrefix                               | FELIX_LOGPREFIX                         | calico-packet                        | The log prefix that Felix uses when rendering LOG rules.  |
| MaxIpsetSize                            | FELIX_MAXIPSETSIZE                      | 1048576                              | Maximum size for the ipsets used by Felix to implement tags. Should be set to a number that is greater than the maximum number of IP addresses that are ever expected in a tag.  |

#### OpenStack specific configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| MetadataAddr                            | FELIX_METADATAADDR                      | 127.0.0.1                            | The IP address or domain name of the server that can answer VM queries for cloud-init metadata. In OpenStack, thiscorresponds to the machine running nova-api (or in Ubuntu, nova-api-metadata). A value of 'None'  (case insensitive) means that Felix should not set up any NAT rule for the metadata path.  |
| MetadataPort                            | FELIX_METADATAPORT                      | 8775                                 | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be changed.  |

#### Bare metal specific configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| InterfacePrefix                         | FELIX_INTERFACEPREFIX                   | cali                                 | The interface name prefix that identifies workload endpoints and so distinguishes them from host endpoint interfaces.  Note: in environments other than bare metal, the orchestrators configure this appropriately.  For example our Kubernetes and Docker integrations set the 'cali' value, and our OpenStack integration sets the 'tap' value. |

Environment variables
---------------------

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
a global setting and a per-host override.  Datastore-based configuration
can be set using the `--raw=felix` option of the calicoctl tool.  For example,
to set a per-host override for "myhost" to move the log file to /tmp/felix.log:

    ./calicoctl config set --raw=felix --node=myhost LogFilePath /tmp/felix.log

(For a global setting, omit the `--node=` option.)

For more information, see the [calicoctl config documentation](../calicoctl/commands/config).
