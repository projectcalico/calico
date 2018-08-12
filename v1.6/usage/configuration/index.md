---
title: Configuring Calico
sitemap: false 
---

This page describes how to configure Calico. We first describe the
configuration of the core Calico component -- Felix --because this is
needed, and configured similarly, regardless of the surrounding
environment (OpenStack, Docker, or whatever). Then, depending on that
surrounding environment, there will be some further configuration of
that environment needed, to tell it to talk to the Calico components.

Currently we have detailed environment configuration only for OpenStack.
Work on other environments is in progress, and this page will be
extended as that happens.

This page aims to be a complete Calico configuration reference, and
hence to describe all the possible fields, files etc. For a more
task-based approach, when installing Calico with OpenStack on Ubuntu or
Red Hat, please see our [Ubuntu]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/ubuntu) or [Red Hat]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation/redhat)  installation guides.

## System configuration

A common problem on Linux systems is running out of space in the
conntrack table, which can cause poor iptables performance. This can
happen if you run a lot of workloads on a given host, or if your
workloads create a lot of TCP connections or bidirectional UDP streams.

To avoid this becoming a problem, we recommend increasing the conntrack
table size. To do so, run the following commands:

    sysctl -w net.netfilter.nf_conntrack_max=1000000
    echo "net.netfilter.nf_conntrack_max=1000000" >> /etc/sysctl.conf

## Felix configuration

The core Calico component is Felix. (Please see [this document]({{site.baseurl}}/{{page.version}}/reference/architecture) for more on  the Calico architecture.)

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

In OpenStack, we recommend putting all configuration into configuration
files, since the etcd database is transient (and may be recreated by the
OpenStack plugin in certain error cases). However, in a Docker
environment the use of environment variables or etcd is often more
convenient.

The full list of parameters which can be set is as follows.


| Setting                     | Default           | Meaning                                 |
|-----------------------------|-------------------|-----------------------------------------|
| EtcdAddr                    | localhost:4001    | The location (IP / hostname and port) of the etcd node or proxy that Felix should connect to.                      |
| EtcdScheme                  | http              | The protocol type (http or https) of the etcd node or proxy that Felix connects to.                            |
| EtcdKeyFile                 | None              | The full path to the etcd private key file, as described in usingtlswithetcd  |
| EtcdCertFile                | None              | The full path to the etcd certificate file, as described in usingtlswithetcd  |
| EtcdCaFile                  | "/etc/ssl/certs/ca-certificates.crt" | The full path to the etcd Certificate Authority certificate file, as described in usingtlswithetcd. The default value is the standard location of the system trust store. To disable authentication of the server by Felix, set the value to "none".                |
| DefaultEndpointToHostAction | DROP              | By default Calico blocks traffic from   endpoints to the host itself by using   an iptables DROP action. If you want to allow some or all traffic from endpoint to host then set this parameter to "RETURN" (which causes the rest of the  iptables INPUT chain to be processed)   or "ACCEPT" (which immediately accepts  packets). |
| FelixHostname               | socket.gethostname() | The hostname Felix reports to the plugin. Should be used if the hostname  Felix autodetects is incorrect or does  not match what the plugin will expect. |
| MetadataAddr                | 127.0.0.1         | The IP address or domain name of the server that can answer VM queries for  cloud-init metadata. In OpenStack, thiscorresponds to the machine running     nova-api (or in Ubuntu, nova-api-metadata). A value of 'None'  (case insensitive) means that Felix should not set up any NAT rule for the metadata path. |
| MetadataPort                | 8775              | The port of the metadata server. This, combined with global.MetadataAddr (if  not 'None'), is used to set up a NAT   rule, from 169.254.169.254:80 to       MetadataAddr:MetadataPort. In most cases this should not need to be       changed. |
| InterfacePrefix             | cali              | The expected prefix for interface names for workload interfaces. For example,   in OpenStack deployments, this should   be set to "tap". Calico polices all     traffic to/from interfaces with this    prefix. Calico blocks traffic to/from   such interfaces by default. |
|-----------------------------|-------------------|-----------------------------------------|
| LogFilePath                 | /var/log/calico/felix.log | The full path to the felix log. Set to "none" to disable file logging. |
|-----------------------------|-------------------|-----------------------------------------|
| EtcdDriverLogFilePath       | /var/log/calico/felix.log | Felix's etcd driver has its own log file. This parameter contains its full path. |
| LogSeveritySys              | ERROR             | The log severity above which logs are sent to the syslog. Valid values are  DEBUG, INFO, WARNING, ERROR and       CRITICAL, or NONE for no logging to   syslog (all values case insensitive). |
| LogSeverityFile             | INFO | The log severity above which logs are sent to the log file. Valid values as for LogSeveritySys. |
| LogSeverityScreen           | ERROR             | The log severity above which logs are sent to the stdout. Valid values as for LogSeveritySys. |
| StartupCleanupDelay         | 30                | Delay, in seconds, before felix does its start-of-day cleanup to remove  orphaned iptables chains and ipsets.  Before the first cleanup, felix     operates in "graceful restart" mode,  during which it preserves any      pre-existing chains and ipsets. In a large deployment you may want to  increase this value to give felix more  time to load the initial snapshot from  etcd before cleaning up. |
| PeriodicResyncInterval      | 3600              | Period, in seconds, at which felix does a full resync with etcd and reprograms iptables/ipsets. Set to 0 to disable periodic resync. |
| IptablesRefreshInterval     | 60                | Period, in seconds, at which felix re-applies all iptables state to ensure that no other process has accidentally broken Calico's rules. Set to 0 to disable iptables refresh. |
| MaxIpsetSize                | 1048576           | Maximum size for the ipsets used by      Felix to implement tags. Should be set   to a number that is greater than the     maximum number of IP addresses that are  ever expected in a tag. |
| IptablesMarkMask            | 0xff000000        | Mask that Felix selects its IPTables Mark bits from. Should be a 32 bit       hexadecimal number with at least 8 bits  set, none of which clash with any other  mark bits in use on the system. |
| PrometheusMetricsEnabled    | "false"           | Set to "true" to enable the experimental Prometheus metrics server in Felix. |
| PrometheusMetricsPort       | 9091              | TCP port that the Prometheus metrics server should bind to.                  |
| EtcdDriverPrometheusMetricsPort | 9092              | TCP port that the Prometheus metrics server in the etcd driver process should bind to. |
| UsageReportingEnabled | "true"              | Reports anonymous Calico version number and cluster size to projectcalico.org.  Logs warnings returned by the usage server. For example, if a significant security vulnerability has been discovered in the version of Calico being used. |
| FailsafeInboundHostPorts    | 22                | Comma-delimited list of TCP ports that Felix will allow incoming traffic to host endpoints on irrespective of the security policy. To disable all inbound host ports, use the value "none". This is useful to avoid accidently cutting off a host with incorrect configuration. The default value allows ssh access.  |
| FailsafeOutboundHostPorts   | 2379,2380,4001,7001  | Comma-delimited list of TCP ports that Felix will allow outgoing from traffic from host endpoints to irrespective of the security policy. To disable all outbound host ports, use the value "none". This is useful to avoid accidently cutting off a host with incorrect configuration. The default value opens etcd's standard ports to ensure that Felix does not get cut off from etcd.  |

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

### etcd configuration

> **NOTE**
>
> etcd configuration cannot be used to set either EtcdAddr or
>
> :   FelixHostname, both of which are required before the etcd
>     configuration can be read.
>

etcd configuration is read from etcd from two places.

1.  For a host of FelixHostname value `HOSTNAME` and a parameter named
    `NAME`, it is read from `/calico/v1/host/HOSTNAME/config/NAME`.
2.  For a parameter named `NAME`, it is read from
    `/calico/v1/config/NAME`.

Note that the names are case sensitive.

## OpenStack environment configuration

When running Calico with OpenStack, you also need to configure various
OpenStack components, as follows.

### Nova (/etc/nova/nova.conf)

Calico uses the Nova metadata service to provide metadata to VMs,
without any proxying by Neutron. To make that work:

-   An instance of the Nova metadata API must run on every compute node.
-   `/etc/nova/nova.conf` must not set `service_neutron_metadata_proxy`
    or `service_metadata_proxy` to `True`. (The default `False` value is
    correct for a Calico cluster.)

### Neutron server (/etc/neutron/neutron.conf)

In `/etc/neutron/neutron.conf` you need the following settings to
configure the Neutron service.

| Setting            | Value                                | Meaning              |
|--------------------|--------------------------------------|----------------------|
| core_plugin        | neutron.plugins.ml2.plugin.ML2Plugin | Use ML2 plugin       |
|--------------------|--------------------------------------|----------------------|

With OpenStack releases earlier than Liberty you will also need:

| Setting                 | Value                    | Meaning                    |
|-------------------------|--------------------------|----------------------------|
| dhcp_agents_per_network | 9999                     | Allow unlimited DHCP agents per network |

Optionally -- depending on how you want the Calico mechanism driver to
connect to the Etcd cluster -- you can also set the following options in
the `[calico]` section of `/etc/neutron/neutron.conf`.

| Setting   | Default Value | Meaning                                   |
|-----------|---------------|-------------------------------------------|
| etcd_host | localhost     | The hostname or IP of the etcd node/proxy |
| etcd_port | 4001          | The port to use for the etcd node/proxy   |

### ML2 (.../ml2_conf.ini)

In `/etc/neutron/plugins/ml2/ml2_conf.ini` you need the following
settings to configure the ML2 plugin.

| Setting              | Value       | Meaning                           |
|----------------------|-------------|-----------------------------------|
| mechanism_drivers    | calico      | Use Calico                        |
| type_drivers         | local, flat | Allow 'local' and 'flat' networks |
| tenant_network_types | local, flat | Allow 'local' and 'flat' networks |

DHCP agent (.../dhcp_agent.ini)
--------------------------------

With OpenStack releases earlier than Liberty, in
`/etc/neutron/dhcp_agent.ini` you need the following setting to
configure the Neutron DHCP agent.

| Setting          | Value                 | Meaning                                                                                              |
|------------------|-----------------------|------------------------------------------------------------------------------------------------------|
| interface_driver | RoutedInterfaceDriver | Use Calico's modified DHCP agent support for TAP interfaces that are routed instead of being bridged |
