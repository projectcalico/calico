---
title: Configuring Felix
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
| DatastoreDriver                         | FELIX_DATASTOREDRIVER                   | etcdv2                               | One of "etcdv2" or "kubernetes".  The datastore that Felix should read endpoints and policy information from.  |
| FelixHostname                           | FELIX_FELIXHOSTNAME                     | socket.gethostname()                 | The hostname Felix reports to the plugin. Should be used if the hostname Felix autodetects is incorrect or does not match what the plugin will expect.  |
| LogFilePath                             | FELIX_LOGFILEPATH                       | /var/log/calico/felix.log            | The full path to the felix log. Set to "none" to disable file logging.  |
| LogSeveritySys                          | FELIX_LOGSEVERITYSYS                    | ERROR                                | The log severity above which logs are sent to the syslog. Valid values are DEBUG, INFO, WARNING, ERROR and CRITICAL, or NONE for no logging to syslog (all values case insensitive).  |
| LogSeverityFile                         | FELIX_LOGSEVERITYFILE                   | INFO                                 | The log severity above which logs are sent to the log file. Valid values as for LogSeveritySys.  |
| LogSeverityScreen                       | FELIX_LOGSEVERITYSCREEN                 | ERROR                                | The log severity above which logs are sent to the stdout. Valid values as for LogSeveritySys.  |
| StartupCleanupDelay                     | FELIX_STARTUPCLEANUPDELAY               | 30                                   | Delay, in seconds, before felix does its start-of-day cleanup to remove orphaned iptables chains and ipsets.  Before the first cleanup, felix operates in "graceful restart" mode,  during which it preserves any pre-existing chains and ipsets. In a large deployment you may want to increase this value to give felix more time to load the initial snapshot from etcd before cleaning up.  |
| PrometheusMetricsEnabled                | FELIX_PROMETHEUSMETRICSENABLED          | "false"                              | Set to "true" to enable the experimental Prometheus metrics server in Felix.  |
| PrometheusMetricsPort                   | FELIX_PROMETHEUSMETRICSPORT             | 9091                                 | Experimental: TCP port that the Prometheus metrics server should bind to.  |
| UsageReportingEnabled                   | FELIX_USAGEREPORTINGENABLED             | "true"                               | Reports anonymous Calico version number and cluster size to projectcalico.org.  Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of Calico being used.  |
| FailsafeInboundHostPorts                | FELIX_FAILSAFEINBOUNDHOSTPORTS          | 22                                   | Comma-delimited list of TCP ports that Felix will allow incoming traffic to host endpoints on irrespective of the security policy. This is useful to avoid accidently cutting off a host with incorrect configuration. The default value allows ssh access.  |
| FailsafeOutboundHostPorts               | FELIX_FAILSAFEOUTBOUNDHOSTPORTS         | 2379,2380,4001,7001                  | Comma-delimited list of TCP ports that Felix will allow outgoing from traffic from host endpoints to irrespective of the security policy. This is useful to avoid accidently cutting off a host with incorrect configuration. The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd.  |
| ReportingIntervalSecs                   | FELIX_REPORTINGINTERVALSECS             | 30                                   | Interval at which Felix reports its status into the datastore or 0 to disable.  Must be non-zero in OpenStack deployments.  |
| ReportingTTLSecs                        | FELIX_REPORTINGTTLSECS                  | 90                                   | Time-to-live setting for process-wide status reports. |

#### etcdv2 datastore configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| EtcdEndpoints                           | FELIX_ETCDENDPOINTS                     | "EtcdScheme://EtcdAddr"              | Comma-delimited list of etcd endpoints to connect to; for example "http://etcd1:2379,http://etcd2:2379".  |
| _Deprecated_ EtcdAddr                   | FELIX_ETCDADDR                          | 127.0.0.1:2379                       | The location (IP / hostname and port) of the etcd node or proxy that Felix should connect to.  |
| _Deprecated_ EtcdScheme                 | FELIX_ETCDSCHEME                        | http                                 | The protocol type (http or https) of the etcd node or proxy that Felix connects to.  |
| EtcdKeyFile                             | FELIX_ETCDKEYFILE                       | None                                 | The full path to the etcd public key file, as described in usingtlswithetcd  |
| EtcdCertFile                            | FELIX_ETCDCERTFILE                      | None                                 | The full path to the etcd certificate file, as described in usingtlswithetcd  |
| EtcdCaFile                              | FELIX_ETCDCAFILE                        | "/etc/ssl/certs/ca-certificates.crt" | The full path to the etcd Certificate Authority certificate file, as described in usingtlswithetcd. The default value is the standard location of the system trust store. To disable authentication of the server by Felix, set the value to "none".  |

#### Kubernetes datastore configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| N/A                                     | N/A                                     |                                      | The Kubernetes datastore driver reads its configuration from Kubernetes-provided environment variables.  |


#### iptables dataplane configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| DefaultEndpointToHostAction             | FELIX_DEFAULTENDPOINTTOHOSTACTION       | DROP                                 | By default Calico blocks traffic from endpoints to the host itself by using an iptables DROP action. If you want to allow some or all traffic from endpoint to host then set this parameter to "RETURN" (which causes the rest of the iptables INPUT chain to be processed)   or "ACCEPT" (which immediately accepts packets).  |
| IptablesMarkMask                        | FELIX_IPTABLESMARKMASK                  | 0xff000000                           | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit hexadecimal number with at least 8 bits set, none of which clash with any other mark bits in use on the system.  |
| IptablesRefreshInterval                 | FELIX_IPTABLESREFRESHINTERVAL           | 60                                   | Period, in seconds, at which felix re-applies all iptables state to ensure that no other process has accidentally broken Calico's rules. Set to 0 to disable iptables refresh.  |
| ChainInsertMode                         | FELIX_CHAININSERTMODE                   | insert                               | One of "insert" or "append".  Controls whether Felix hooks the kernel's top-level iptables chains by inserting a rule at the top of the chain or by appending a rule at the bottom.  "insert" is the safe default since it prevents Calico's rules from being bypassed.  If you switch to "append" mode, be sure that the other rules in the chains signal acceptance by falling through to the Calico rules, otherwise the Calico policy will be bypassed.  |
| LogPrefix                               | FELIX_LOGPREFIX                         | calico-drop                          | The log prefix that Felix uses when rendering DROP rules.  |
| MaxIpsetSize                            | FELIX_MAXIPSETSIZE                      | 1048576                              | Maximum size for the ipsets used by Felix to implement tags. Should be set to a number that is greater than the maximum number of IP addresses that are ever expected in a tag.  |

#### OpenStack specific configuration

| Setting                                 | Environment variable                    | Default                              | Meaning                                 |
|-----------------------------------------|-----------------------------------------|--------------------------------------|-----------------------------------------|
| MetadataAddr                            | FELIX_METADATAADDR                      | 127.0.0.1                            | The IP address or domain name of the server that can answer VM queries for cloud-init metadata. In OpenStack, thiscorresponds to the machine running nova-api (or in Ubuntu, nova-api-metadata). A value of 'None'  (case insensitive) means that Felix should not set up any NAT rule for the metadata path.  |
| MetadataPort                            | FELIX_METADATAPORT                      | 8775                                 | The port of the metadata server. This, combined with global.MetadataAddr (if not 'None'), is used to set up a NAT rule, from 169.254.169.254:80 to MetadataAddr:MetadataPort. In most cases this should not need to be changed.  |

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

### etcd configuration

> **NOTE**
>
> etcd configuration cannot be used to set either EtcdAddr or
>
> :   FelixHostname, both of which are required before the etcd
>     configuration can be read.
>

when using the etcd datastore driver, etcd configuration is read from
etcd from two places.

1.  For a host of FelixHostname value `HOSTNAME` and a parameter named
    `NAME`, it is read from `/calico/v1/host/HOSTNAME/config/NAME`.
2.  For a parameter named `NAME`, it is read from
    `/calico/v1/config/NAME`.

Note that the names are case sensitive.
