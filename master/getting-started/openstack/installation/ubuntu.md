---
title: Ubuntu packaged install instructions
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/openstack/installation/ubuntu'
---

These instructions will take you through a first-time install of {{site.prodname}} using
the latest packages on an Ubuntu system. If you are upgrading an existing system, please see [this
document]({{site.baseurl}}/{{page.version}}/getting-started/openstack/upgrade)
instead for upgrade instructions.

There are three sections to the install: installing etcd, upgrading
control nodes to use {{site.prodname}}, and upgrading compute nodes to use {{site.prodname}}.
The [Common Steps](#common-steps) must be followed on each node before moving onto
the specific instructions in those sections.

## Before you begin

- Ensure that you meet the [requirements](../requirements). 
- Confirm that you have SSH access to and root privileges on one or more Ubuntu hosts
  (your OpenStack compute or control nodes).
- [Install OpenStack with Neutron and ML2 networking](http://docs.openstack.org)
  on the Ubuntu hosts.

## Common steps

Some steps need to be taken on all machines being installed with {{site.prodname}}.
These steps are detailed in this section.

### Configuring APT software sources

{% include ppa_repo_name %}

Configure APT to use the {{site.prodname}} PPA:

```
add-apt-repository ppa:project-calico/{{ ppa_repo_name }}
```

### Common

You will also need to add the official [BIRD](http://bird.network.cz/)
PPA. This PPA contains fixes to BIRD that are not yet available in Ubuntu. To
add the PPA, run:

```
add-apt-repository ppa:cz.nic-labs/bird
```

Once that's done, update your package manager on each machine:

```
apt-get update
```

## etcd install

{{site.prodname}} requires an etcd database to operate. This may be installed on
a single machine or as a cluster.

These instructions cover installing a single node etcd database. You may
wish to co-locate this with your control node. If you want to install a
cluster, please get in touch with us and we'll be happy to help you
through the process.

1.  Install the `etcd` packages.

    ```
    apt-get install etcd python-etcd
    ```

1.  Stop the etcd service.

    ```
    service etcd stop
    ```

1.  Delete any existing etcd database.

    ```
    rm -rf /var/lib/etcd/*
    ```

1.  Mount a RAM disk at /var/lib/etcd.

    ```
    mount -t tmpfs -o size=512m tmpfs /var/lib/etcd
    ```

1. Add the following to the bottom of `/etc/fstab` so that the RAM disk
   gets reinstated at boot time.

   ```
   tmpfs /var/lib/etcd tmpfs nodev,nosuid,noexec,nodiratime,size=512M 0 0
   ```

1. Open `/etc/init/etcd.conf` for editing and find the line which begins 
   `exec /usr/bin/etcd`. Replace `<controller_fqdn>` and `<controller_ip>` 
   with the appropriate values.

   ```
   exec /usr/bin/etcd --name="<controller_fqdn>"  \
                      --advertise-client-urls="http://<controller_ip>:2379,http://<controller_ip>:4001"  \
                      --listen-client-urls="http://0.0.0.0:2379,http://0.0.0.0:4001"  \
                      --listen-peer-urls "http://0.0.0.0:2380"  \
                      --initial-advertise-peer-urls "http://<controller_ip>:2380"  \
                      --initial-cluster-token $(uuidgen)  \
                      --initial-cluster "<controller_fqdn>=http://<controller_ip>:2380"  \
                      --initial-cluster-state "new"
   ```

1. Start the etcd service.

   ```
   service etcd start
   ```

## etcd proxy install

Install an etcd proxy on every node running OpenStack services that
isn't running the etcd database itself (both control and compute nodes).

1.  Install the `etcd` and `python-etcd` packages.

    ```
    apt-get install etcd python-etcd
    ```

1.  Stop the etcd service.

    ```
    service etcd stop
    ```

1.  Delete any existing etcd database.

    ```
    rm -rf /var/lib/etcd/*
    ```

1. Open `/etc/init/etcd.conf` for editing and find the line which begins 
   `exec /usr/bin/etcd`. Replace `<etcd_fqdn>` and `<etcd_ip>` with the
   appropriate values.

   ```
   exec /usr/bin/etcd --proxy on                                             \
                      --initial-cluster "<etcd_fqdn>=http://<etcd_ip>:2380"  \
   ```

1. Start the etcd service.

    ```
    service etcd start
    ```

## Control node install

On each control node ensure etcd or an etcd proxy is installed, and then
perform the following steps.

1.  Run `apt-get upgrade` and `apt-get dist-upgrade`. These commands
    will bring in {{site.prodname}}-specific updates to the OpenStack packages and
    to `dnsmasq`. 

1.  Install the `etcd3gw` Python package, if it is not already installed on
    your system.  `etcd3gw` is needed by {{site.prodname}}'s OpenStack driver but not yet
    packaged for Ubuntu, so you should install it with `pip`.  First check in
    case it has already been pulled in by your OpenStack installation.

    ```
    find /usr/lib/python2.7/ -name etcd3gw
    ```

    If you see no output there, install `etcd3gw` with pip.

    ```
    apt-get install -y python-pip
    pip install etcd3gw
    ```

1.  Install the `calico-control` package:

    ```
    apt-get install calico-control
    ```

1.  Edit the `/etc/neutron/neutron.conf` file. In the `[DEFAULT]`
    section, find the line beginning with `core_plugin`, and change it to
    read `core_plugin = calico`.

1.  Restart the Neutron server process:

    ```
    service neutron-server restart
    ```

## Compute node install

On each compute node ensure etcd or an etcd proxy is installed, and then
perform the following steps:

1.  Make the changes to SELinux and QEMU config that are described in
    [this libvirt Wiki page](https://web.archive.org/web/20160226213437/http://wiki.libvirt.org/page/Guest_won't_start_-_warning:_could_not_open_/dev/net/tun_('generic_ethernet'_interface)),
    to allow VM interfaces with `type='ethernet'`.

    Disable SELinux if it's running. SELinux isn't installed by default
    on Ubuntu. You can check its status by running `sestatus`. If this
    is installed and the current mode is `enforcing`, then disable it by
    running `setenforce permissive` and setting `SELINUX=permissive` in
    `/etc/selinux/config`.

    In `/etc/libvirt/qemu.conf`, add or edit the following four options
    (in particular note the `/dev/net/tun` in `cgroup_device_acl`):

    ```
    clear_emulator_capabilities = 0
    user = "root"
    group = "root"
    cgroup_device_acl = [
        "/dev/null", "/dev/full", "/dev/zero",
        "/dev/random", "/dev/urandom",
        "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
        "/dev/rtc", "/dev/hpet", "/dev/net/tun",
    ]
    ```

    Then restart libvirt to pick up the changes:

    ```
    service libvirt-bin restart
    ```

1.  Open `/etc/nova/nova.conf` and remove the line from the `[DEFAULT]`
    section that reads:

    ```
    linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver
    ```

    Remove the lines from the `[neutron]` section setting
    `service_neutron_metadata_proxy` or `service_metadata_proxy` to
    `True`, if there are any.

    Restart nova compute.

    ```
    service nova-compute restart
    ```

1.  If they're running, stop the Open vSwitch services:

    ```
    service openvswitch-switch stop
    service neutron-plugin-openvswitch-agent stop
    ```

    Then, prevent the services running if you reboot:

    ```
    sh -c "echo 'manual' > /etc/init/openvswitch-switch.override"
    sh -c "echo 'manual' > /etc/init/openvswitch-force-reload-kmod.override"
    sh -c "echo 'manual' > /etc/init/neutron-plugin-openvswitch-agent.override"
    ```

    Then, on your control node, run the following command to find the
    agents that you just stopped:

    ```
    neutron agent-list
    ```

    For each agent, delete them with the following command on your
    control node, replacing `<agent-id>` with the ID of the agent:

    ```
    neutron agent-delete <agent-id>
    ```

1.  Install some extra packages:

    ```
    apt-get install neutron-common neutron-dhcp-agent nova-api-metadata
    ```

1.  Run `apt-get upgrade` and `apt-get dist-upgrade`. These commands
    will bring in {{site.prodname}}-specific updates to the OpenStack packages and
    to `dnsmasq`. 
    
1.  Install the {{site.prodname}} DHCP agent (which uses etcd, allowing 
    it to scale to higher numbers of hosts) and disable the Neutron-provided 
    one:

    ```
    service neutron-dhcp-agent stop
    echo manual | tee /etc/init/neutron-dhcp-agent.override
    apt-get install calico-dhcp-agent
    ```

1.  Install the `calico-compute` package:

    ```
    apt-get install calico-compute
    ```

    This step may prompt you to save your IPTables rules to make them
    persistent on restart -- hit yes.

1.  Configure BIRD. By default {{site.prodname}} assumes that you'll be deploying a
    route reflector to avoid the need for a full BGP mesh. To this end,
    it includes useful configuration scripts that will prepare a BIRD
    config file with a single peering to the route reflector. If that's
    correct for your network, you can run either or both of the
    following commands.

    For IPv4 connectivity between compute hosts:

    ```
    calico-gen-bird-conf.sh <compute_node_ip> <route_reflector_ip> <bgp_as_number>
    ```

    And/or for IPv6 connectivity between compute hosts:

    ```
    calico-gen-bird6-conf.sh <compute_node_ipv4> <compute_node_ipv6> <route_reflector_ipv6> <bgp_as_number>
    ```

    Note that you'll also need to configure your route reflector to
    allow connections from the compute node as a route reflector client.
    If you are using BIRD as a route reflector, follow the instructions
    [here]({{site.baseurl}}/{{page.version}}/usage/routereflector/bird-rr-config). If you are using another route reflector, refer
    to the appropriate instructions to configure a client connection.

    If you *are* configuring a full BGP mesh you'll need to handle the
    BGP configuration appropriately on each compute host. The scripts
    above can be used to generate a sample configuration for BIRD, by
    replacing the `<route_reflector_ip>` with the IP of one other
    compute host -- this will generate the configuration for a single
    peer connection, which you can duplicate and update for each compute
    host in your mesh.

    To maintain connectivity between VMs if BIRD crashes or is upgraded,
    configure BIRD graceful restart:

    -   Add `-R` to `BIRD\_ARGS` in /etc/bird/envvars (you may need to
        uncomment this option).
    -   Edit the upstart jobs /etc/init/bird.conf and bird6.conf (if
        you're using IPv6), and add the following script to it.

        ```
        pre-stop script
        PID=`status bird | egrep -oi '([0-9]+)$' | head -n1`
        kill -9 $PID
        end script
        ```

1.  Create the `/etc/calico/felix.cfg` file by taking a copy of the
    supplied sample config at `/etc/calico/felix.cfg.example`.
    
1. Restart the Felix service with `service calico-felix restart`.
