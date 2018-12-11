---
title: 'Ubuntu Packaged Install Instructions'
canonical_url: 'https://docs.projectcalico.org/v3.4/getting-started/openstack/installation/ubuntu'
---

These instructions will take you through a first-time install of Calico using
the latest packages on a system running Ubuntu 14.04 (Trusty) or 16.04
(Xenial), with OpenStack Icehouse, Juno, Kilo, Liberty or Mitaka. If you are
upgrading an existing system, please see [this document]({{site.baseurl}}/{{page.version}}/getting-started/openstack/upgrade) instead
for upgrade instructions.

There are three sections to the install: installing etcd, upgrading
control nodes to use Calico, and upgrading compute nodes to use Calico.
The **Common Steps** must be followed on each node before moving onto
the specific instructions in those sections.

## Prerequisites

Before starting this you will need the following:

-   One or more machines running Ubuntu (these will be installed
    as your OpenStack compute or control nodes).
-   SSH access to these machines.

## Common Steps

Some steps need to be taken on all machines being installed with Calico.
These steps are detailed in this section.

### Install OpenStack

If you haven't already done so, you should install OpenStack with
Neutron and ML2 networking. Instructions for installing OpenStack can be
found at <http://docs.openstack.org>.

### Configuring the APT software sources

The latest version of Calico for OpenStack is 1.4, and we recommend using it
with OpenStack Liberty or later.  Other possible combinations are shown by the
following table.

| OpenStack release     | Calico version | Ubuntu versions | PPAs             |
|-----------------------+----------------+-----------------+------------------|
| Mitaka                |            1.4 | Xenial, Trusty  | calico-1.6       |
| Liberty               |            1.4 | Xenial, Trusty  | calico-1.6       |
| Kilo                  |            1.4 | Trusty          | calico-1.6, kilo |
| (deprecated) Kilo     |            1.3 | Trusty          | kilo             |
| (deprecated) Juno     |            1.3 | Trusty          | juno             |
| (deprecated) Icehouse |            1.3 | Trusty          | icehouse         |

For your chosen combination, you need to configure APT to use the corresponding
PPA(s).  For example, for Calico 1.4 with Liberty or later:

```shell
    $ sudo add-apt-repository ppa:project-calico/calico-1.6
```

Before OpenStack Liberty, Calico needed patched versions of Nova and Neutron.
If you're using a version of OpenStack prior to Liberty, edit
`/etc/apt/preferences` to add the following lines, whose effect is to prefer
Calico-provided packages for Nova and Neutron even if later versions of those
packages are released by Ubuntu.

```
    Package: *
    Pin: release o=LP-PPA-project-calico-*
    Pin-Priority: 1001
```

### Common

You will also need to add the official [BIRD](http://bird.network.cz/)
PPA. This PPA contains fixes to BIRD that are not yet available in Ubuntu. To
add the PPA, run:

```shell
    $ sudo add-apt-repository ppa:cz.nic-labs/bird
```

Once that's done, update your package manager on each machine:

```shell
    $ sudo apt-get update
```

## Etcd Install

Calico requires an etcd database to operate -- this may be installed on
a single machine or as a cluster.

These instructions cover installing a single node etcd database. You may
wish to co-locate this with your control node. If you want to install a
cluster, please get in touch with us and we'll be happy to help you
through the process.

1.  Install the `etcd` packages:

    ```shell
        $ sudo apt-get install etcd python-etcd
    ```

2.  Stop the etcd service: :

    ```shell
        $ sudo service etcd stop
    ```

3.  Delete any existing etcd database: :

    ```shell
        $ sudo rm -rf /var/lib/etcd/*
    ```

4.  Mount a RAM disk at /var/lib/etcd: :

    ```shell
        $ sudo mount -t tmpfs -o size=512m tmpfs /var/lib/etcd
    ```

5.  Add the following to the bottom of `/etc/fstab` so that the RAM disk
    gets reinstated at boot time:

    ```shell
        tmpfs /var/lib/etcd tmpfs nodev,nosuid,noexec,nodiratime,size=512M 0 0
    ```

6.  Edit `/etc/init/etcd.conf`:
    -   Find the line which begins `exec /usr/bin/etcd` and edit it,
        substituting for `<controller_fqdn>` and
        `<controller_ip>` appropriately.

        ```shell
            exec /usr/bin/etcd --name="<controller_fqdn>"  \
                               --advertise-client-urls="http://<controller_ip>:2379,http://<controller_ip>:4001"  \
                               --listen-client-urls="http://0.0.0.0:2379,http://0.0.0.0:4001"  \
                               --listen-peer-urls "http://0.0.0.0:2380"  \
                               --initial-advertise-peer-urls "http://<controller_ip>:2380"  \
                               --initial-cluster-token $(uuidgen)  \
                               --initial-cluster "<controller_fqdn>=http://<controller_ip>:2380"  \
                               --initial-cluster-state "new"
        ```

7.  Start the etcd service: :

    ```shell
        $ sudo service etcd start
    ```

## Etcd Proxy Install

Install an etcd proxy on every node running OpenStack services that
isn't running the etcd database itself (both control and compute nodes).

1.  Install the `etcd` and `python-etcd` packages:

    ```shell
        $ sudo apt-get install etcd python-etcd
    ```

2.  Stop the etcd service: :

    ```shell
        $ sudo service etcd stop
    ```

3.  Delete any existing etcd database: :

    ```shell
        $ sudo rm -rf /var/lib/etcd/*
    ```

4.  Edit `/etc/init/etcd.conf`:
    -   Find the line which begins `exec /usr/bin/etcd` and edit it,
        substituting for `<etcd_fqdn>` and `<etcd_ip>` appropriately:

        ```shell
            exec /usr/bin/etcd --proxy on                                             \
                               --initial-cluster "<etcd_fqdn>=http://<etcd_ip>:2380"  \
        ```

5.  Start the etcd service:

    ```shell
        $ sudo service etcd start
    ```

## Control Node Install

On each control node ensure etcd or an etcd proxy is installed, and then
perform the following steps:

1.  Run `apt-get upgrade` and `apt-get dist-upgrade`. These commands
    will bring in Calico-specific updates to the OpenStack packages and
    to `dnsmasq`. (OpenStack updates are not needed for Liberty.)

2.  Install the `calico-control` package:

    ```shell
        $ sudo apt-get install calico-control
    ```

3.  Edit the `/etc/neutron/neutron.conf` file. In the [DEFAULT]
    section:
    -   Find the line beginning with `core_plugin`, and change it to
        read `core_plugin = calico`.

4.  With OpenStack releases earlier than Liberty, edit the
    `/etc/neutron/neutron.conf` file. In the [DEFAULT] section:
    -   Find the line for the `dhcp_agents_per_network` setting,
        uncomment it, and set its value to the number of compute nodes
        that you will have (or any number larger than that). This allows
        a DHCP agent to run on every compute node, which Calico requires
        because the networks on different compute nodes are not
        bridged together.

5.  Restart the Neutron server process:

    ```shell
        $ sudo service neutron-server restart
    ```

## Compute Node Install

On each compute node ensure etcd or an etcd proxy is installed, and then
perform the following steps:

1.  Make the changes to SELinux and QEMU config that are described in
    [this libvirt Wiki page](https://web.archive.org/web/20160226213437/http://wiki.libvirt.org/page/Guest_won't_start_-_warning:_could_not_open_/dev/net/tun_('generic_ethernet'_interface)),
    to allow VM interfaces with `type='ethernet'`.

    Disable SELinux if it's running. SELinux isn't installed by default
    on Ubuntu -- you can check its status by running `sestatus`. If this
    is installed and the current mode is `enforcing`, then disable it by
    running `setenforce permissive` and setting `SELINUX=permissive` in
    `/etc/selinux/config`.

    In `/etc/libvirt/qemu.conf`, add or edit the following four options
    (in particular note the `/dev/net/tun` in `cgroup_device_acl`):

    ```shell
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

    ```shell
        $ sudo service libvirt-bin restart
    ```

2.  Open `/etc/nova/nova.conf` and remove the line from the \[DEFAULT\]
    section that reads:

    ```shell
        linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver
    ```

    Remove the lines from the \[neutron\] section setting
    `service_neutron_metadata_proxy` or `service_metadata_proxy` to
    `True`, if there are any.

    Restart nova compute.

    ```shell
        $ sudo service nova-compute restart
    ```

3.  If they're running, stop the Open vSwitch services:

    ```shell
        $ sudo service openvswitch-switch stop
        $ sudo service neutron-plugin-openvswitch-agent stop
    ```

    Then, prevent the services running if you reboot:

    ```shell
        $ sudo sh -c "echo 'manual' > /etc/init/openvswitch-switch.override"
        $ sudo sh -c "echo 'manual' > /etc/init/openvswitch-force-reload-kmod.override"
        $ sudo sh -c "echo 'manual' > /etc/init/neutron-plugin-openvswitch-agent.override"
    ```

    Then, on your control node, run the following command to find the
    agents that you just stopped:

    ```shell
        neutron agent-list
    ```

    For each agent, delete them with the following command on your
    control node, replacing `<agent-id>` with the ID of the agent:

    ```shell
        neutron agent-delete <agent-id>
    ```

4.  Install some extra packages:

    ```shell
        $ sudo apt-get install neutron-common neutron-dhcp-agent nova-api-metadata
    ```

5.  Run `apt-get upgrade` and `apt-get dist-upgrade`. These commands
    will bring in Calico-specific updates to the OpenStack packages and
    to `dnsmasq`. For OpenStack Liberty, this step only upgrades
    `dnsmasq`.

    > **WARNING**
    >
    > Check the version of libvirt-bin that is installed using
    > `dpkg -s libvirt-bin`. For Kilo, the version of libvirt-bin
    > should be at least `1.2.12-0ubuntu13`. This will become part
    > of the standard Ubuntu Kilo repository, but at the time of
    > writing needs to be installed as follows:
    >
    >
    >   ```shell
    >      $ sudo add-apt-repository cloud-archive:kilo-proposed
    >      $ sudo apt-get update
    >      $ sudo apt-get upgrade
        ```

6.  If you're using OpenStack Icehouse, Juno or Kilo, open
    `/etc/neutron/dhcp_agent.ini` in your preferred text editor, and set
    the following in the `[DEFAULT]` section:

    ```shell
        interface_driver = neutron.agent.linux.interface.RoutedInterfaceDriver
    ```

    and then restart the DHCP agent:

    ```shell
        $ sudo service neutron-dhcp-agent restart
    ```

    For OpenStack Liberty and later, install the Calico DHCP agent
    (which uses etcd, allowing it to scale to higher numbers of hosts)
    and disable the Neutron-provided one:

    ```shell
        $ sudo service neutron-dhcp-agent stop
        $ echo manual | sudo tee /etc/init/neutron-dhcp-agent.override
        $ sudo apt-get install calico-dhcp-agent
    ```

7.  Install the `calico-compute` package:

    ```shell
        $ sudo apt-get install calico-compute
    ```

    This step may prompt you to save your IPTables rules to make them
    persistent on restart -- hit yes.

8.  Configure BIRD. By default Calico assumes that you'll be deploying a
    route reflector to avoid the need for a full BGP mesh. To this end,
    it includes useful configuration scripts that will prepare a BIRD
    config file with a single peering to the route reflector. If that's
    correct for your network, you can run either or both of the
    following commands.

    For IPv4 connectivity between compute hosts:

    ```shell
        $ sudo calico-gen-bird-conf.sh <compute_node_ip> <route_reflector_ip> <bgp_as_number>
    ```

    And/or for IPv6 connectivity between compute hosts:

    ```shell
        $ sudo calico-gen-bird6-conf.sh <compute_node_ipv4> <compute_node_ipv6> <route_reflector_ipv6> <bgp_as_number>
    ```

    Note that you'll also need to configure your route reflector to
    allow connections from the compute node as a route reflector client.
    If you are using BIRD as a route reflector, follow the instructions
    [here]({{site.baseurl}}/{{page.version}}/usage/bird-rr-config). If you are using another route reflector, refer
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

    -   Add -R to BIRD\_ARGS in /etc/bird/envvars (you may need to
        uncomment this option).
    -   Edit the upstart jobs /etc/init/bird.conf and bird6.conf ()if
        you're using IPv6), and add the following script to it.

        ```shell
            pre-stop script
            PID=`status bird | egrep -oi '([0-9]+)$' | head -n1`
            kill -9 $PID
            end script
        ```

9.  Create the `/etc/calico/felix.cfg` file by taking a copy of the
    supplied sample config at `/etc/calico/felix.cfg.example`.
10. Restart the Felix service with `service calico-felix restart`.
