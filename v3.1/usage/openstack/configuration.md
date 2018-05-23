---
title: Configuring Systems for use with Calico
redirect_from: latest/usage/openstack/configuration
canonical_url: 'https://docs.projectcalico.org/v2.6/usage/openstack/configuration'
---

When running {{site.prodname}} with OpenStack, you also need to configure various
OpenStack components, as follows.

### Nova (/etc/nova/nova.conf)

{{site.prodname}} uses the Nova metadata service to provide metadata to VMs,
without any proxying by Neutron. To make that work:

-   An instance of the Nova metadata API must run on every compute node.
-   `/etc/nova/nova.conf` must not set `service_neutron_metadata_proxy`
    or `service_metadata_proxy` to `True`. (The default `False` value is
    correct for a {{site.prodname}} cluster.)

### Neutron server (/etc/neutron/neutron.conf)

In `/etc/neutron/neutron.conf` you need the following settings to
configure the Neutron service.

| Setting            | Value   | Meaning                                |
|--------------------|---------|----------------------------------------|
| core_plugin        | calico  | Use the {{site.prodname}} core plugin  |
|--------------------|---------|----------------------------------------|

{{site.prodname}} can operate either as a core plugin or as an ML2 mechanism driver.  The
function is the same both ways, except that floating IPs are only supported
when operating as a core plugin; hence the recommended setting here.

However, if you don't need floating IPs and have other reasons for using ML2,
you can, instead, set

| Setting            | Value                                | Meaning              |
|--------------------|--------------------------------------|----------------------|
| core_plugin        | neutron.plugins.ml2.plugin.ML2Plugin | Use ML2 plugin       |
|--------------------|--------------------------------------|----------------------|

and then the further ML2-specific configuration as covered below.

With OpenStack releases earlier than Liberty you will also need:

| Setting                 | Value                    | Meaning                    |
|-------------------------|--------------------------|----------------------------|
| dhcp_agents_per_network | 9999                     | Allow unlimited DHCP agents per network |

The following options in the `[calico]` section of `/etc/neutron/neutron.conf` govern how
the {{site.prodname}} plugin/driver and DHCP agent connect to the {{site.prodname}} etcd
datastore.  You should set `etcd_host` to the IP of your etcd server, and `etcd_port` if
that server is using a non-standard port.  If the etcd server is TLS-secured, also set:

-  `etcd_cert_file` to a client certificate, which must be signed by a Certificate
   Authority that the server trusts

-  `etcd_key_file` to the corresponding private key file

-  `etcd_ca_cert_file` to a file containing data for the Certificate Authorities that you
   trust to sign the etcd server's certificate.

| Setting           | Default Value | Meaning                                                      |
|-------------------|---------------|--------------------------------------------------------------|
| etcd_host         | 127.0.0.1     | The hostname or IP of the etcd server                        |
| etcd_port         | 2379          | The port to use for the etcd node/proxy                      |
| etcd_key_file     |               | The path to the TLS key file to use with etcd                |
| etcd_cert_file    |               | The path to the TLS client certificate file to use with etcd |
| etcd_ca_cert_file |               | The path to the TLS CA certificate file to use with etcd     |

### ML2 (.../ml2_conf.ini)

In `/etc/neutron/plugins/ml2/ml2_conf.ini` you need the following
settings to configure the ML2 plugin.

| Setting              | Value       | Meaning                           |
|----------------------|-------------|-----------------------------------|
| mechanism_drivers    | calico      | Use {{site.prodname}}             |
| type_drivers         | local, flat | Allow 'local' and 'flat' networks |
| tenant_network_types | local, flat | Allow 'local' and 'flat' networks |

DHCP agent (.../dhcp_agent.ini)
--------------------------------

With OpenStack releases earlier than Liberty, in
`/etc/neutron/dhcp_agent.ini` you need the following setting to
configure the Neutron DHCP agent.

| Setting          | Value                 | Meaning                                                                                                         |
|------------------|-----------------------|-----------------------------------------------------------------------------------------------------------------|
| interface_driver | RoutedInterfaceDriver | Use {{site.prodname}}'s modified DHCP agent support for TAP interfaces that are routed instead of being bridged |
