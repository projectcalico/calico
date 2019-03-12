---
title: Configuring Systems for use with Calico
canonical_url: 'https://docs.projectcalico.org/v3.6/usage/openstack/configuration'
---

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

| Setting            | Value   | Meaning                     |
|--------------------|---------|-----------------------------|
| core_plugin        | calico  | Use the Calico core plugin  |
|--------------------|---------|-----------------------------|

Calico can operate either as a core plugin or as an ML2 mechanism driver.  The
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
