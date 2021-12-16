---
title: Floating IPs
description: Configure floating IPs in Calico for OpenStack. 
canonical_url: '/networking/openstack/floating-ips'
---

networking-calico includes beta support for floating IPs.  Currently this
requires running {{site.prodname}} as a Neutron core plugin (i.e. `core_plugin =
calico`) instead of as an ML2 mechanism driver.

> **Note**: We would like it to work as an ML2 mechanism driver too—patches
> and/or advice welcome!
{: .alert .alert-info}

To set up a floating IP, you need the same pattern of Neutron data model
objects as you do for Neutron in general, which means:

- a tenant network, with an instance attached to it, that will be the target of
  the floating IP

- a Neutron router, with the tenant network connected to it

- a provider network with `router:external True` that is set as the
  router's gateway (e.g. with `neutron router-gateway-set`), and with a
  subnet with a CIDR that floating IPs will be allocated from

- a floating IP, allocated from the provider network subnet, that maps onto the
  instance attached to the tenant network.

For example:

1. Create tenant network and subnet.

    ```bash
    neutron net-create --shared calico
    neutron subnet-create --gateway 10.65.0.1 --enable-dhcp --ip-version 4 --name calico-v4 calico 10.65.0.0/24
    ```

1. Boot a VM on that network.

   ```bash
   nova boot [...]
   ```

1. Find its Neutron port ID.

   ```bash
   neutron port-list
   ```

1. Create an external network and subnet; this is where floating
   IPs will be allocated from.

   ```bash
   neutron net-create public --router:external True
   neutron subnet-create public 172.16.1.0/24
   ```

1. Create a router connecting the tenant and external networks.

    ```bash
    neutron router-create router1
    neutron router-interface-add router1 <tenant-subnet-id>
    neutron router-gateway-set router1 public
    ```

1. Create a floating IP and associate it with the target VM.

   ```bash
   neutron floatingip-create public
   neutron floatingip-associate <floatingip-id> <target-VM-port-id>
   ```

   Then the {{site.prodname}} agents will arrange that the floating IP is routed to the
   instance's compute host, and then DNAT'd to the instance's fixed IP address.

1. From a compute node, issue the following command.

   ```bash
   ip r
   ```

    It should return the routing table.

    ```
    default via 10.240.0.1 dev eth0
    10.65.0.13 dev tap9a7e0868-da  scope link
    10.65.0.14 via 192.168.8.4 dev l2tpeth8-3  proto bird
    10.65.0.23 via 192.168.8.4 dev l2tpeth8-3  proto bird
    10.240.0.1 dev eth0  scope link
    172.16.1.3 dev tap9a7e0868-da  scope link
    192.168.8.0/24 dev l2tpeth8-3  proto kernel  scope link  src 192.168.8.3
    192.168.122.0/24 dev virbr0  proto kernel  scope link  src 192.168.122.1
   ```
   {: .no-select-button}

1. Issue the following command to review iptables.

   ```bash
   sudo iptables -L -n -v -t nat
   ```

    It should return something like the following.

    ```
    [...]
    Chain felix-FIP-DNAT (2 references)
     pkts bytes target     prot opt in     out     source               destination
        0     0 DNAT       all  --  *      *       0.0.0.0/0            172.16.1.3           to:10.65.0.13

    Chain felix-FIP-SNAT (1 references)
     pkts bytes target     prot opt in     out     source               destination
        0     0 SNAT       all  --  *      *       10.65.0.13           10.65.0.13           to:172.16.1.3

    Chain felix-OUTPUT (1 references)
     pkts bytes target     prot opt in     out     source               destination
        1    60 felix-FIP-DNAT  all  --  *      *       0.0.0.0/0            0.0.0.0/0

    Chain felix-POSTROUTING (1 references)
     pkts bytes target     prot opt in     out     source               destination
        1    60 felix-FIP-SNAT  all  --  *      *       0.0.0.0/0            0.0.0.0/0

    Chain felix-PREROUTING (1 references)
     pkts bytes target     prot opt in     out     source               destination
        0     0 felix-FIP-DNAT  all  --  *      *       0.0.0.0/0            0.0.0.0/0
        0     0 DNAT       tcp  --  *      *       0.0.0.0/0            169.254.169.254      tcp dpt:80 to:127.0.0.1:8775
    [...]
    ```
    {: .no-select-button}
