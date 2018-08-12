---
title: Ubuntu packaged install instructions
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/openstack/installation/ubuntu'
---

These instructions will take you through a first-time install of
{{site.prodname}}.  If you are upgrading an existing system, please see
[{{site.prodname}} on OpenStack
upgrade]({{site.baseurl}}/{{page.version}}/getting-started/openstack/upgrade)
instead.

There are three sections to the install: installing etcd, adding
{{site.prodname}} to OpenStack control nodes, and adding {{site.prodname}} to
OpenStack compute nodes.  Follow the [Common steps](#common-steps) on each node
before moving on to the specific instructions in the control and compute
sections. If you want to create a combined control and compute node, work
through all three sections.

## Before you begin

- Ensure that you meet the [requirements](../requirements).
- Confirm that you have SSH access to and root privileges on one or more Ubuntu hosts
  (your OpenStack compute or control nodes).
- [Install OpenStack with Neutron and ML2 networking](http://docs.openstack.org)
  on the Ubuntu hosts.

## Common steps

Some steps need to be taken on all machines being installed with {{site.prodname}}.
These steps are detailed in this section.

{% include ppa_repo_name %}

1.  Configure APT to use the {{site.prodname}} PPA:

    ```
    add-apt-repository ppa:project-calico/{{ ppa_repo_name }}
    ```

1.  Add the official [BIRD](http://bird.network.cz/) PPA. This PPA contains
    fixes to BIRD that are not yet available in Ubuntu. To add the PPA, run:

    ```
    add-apt-repository ppa:cz.nic-labs/bird
    ```

    > **Tip**: If the above command fails with error
    > `'ascii' codec can't decode byte`, try running the command with a
    > UTF-8 enabled locale:
    > `LC_ALL=en_US.UTF-8 add-apt-repository ppa:cz.nic-labs/bird`.
    {: .alert .alert-success}

1. Update your package manager on each machine:

    ```
    apt-get update
    ```

1.  Install the `etcd3gw` Python package, if it is not already installed on
    your system.  `etcd3gw` is needed by {{site.prodname}}'s OpenStack driver
    and DHCP agent, but is not yet packaged for Ubuntu, so you should install
    it with `pip`.  First check in case it has already been pulled in by your
    OpenStack installation.

    ```
    find /usr/lib/python2.7/ -name etcd3gw
    ```

    If you see no output there, install `etcd3gw` with pip.

    ```
    apt-get install -y python-pip
    pip install etcd3gw
    ```

## etcd install

{{site.prodname}} operation requires an etcd v3 key/value store—this may be
installed on a single machine or as a cluster.  For production you will likely
want multiple nodes for greater performance and reliability; please refer to
[the upstream etcd docs](https://coreos.com/etcd/) for detailed advice and
setup.

etcd v3 is not packaged for Ubuntu Trusty or Xenial, so to install an etcd
server we suggest one of the following:

- Download the etcd binary from the [official etcd release
  page](https://github.com/coreos/etcd/releases/), and run it as shown by the
  instructions there.

- [Running etcd as a container under
  Docker](https://coreos.com/etcd/docs/latest/op-guide/container.html#docker).

## Control node install

On each control node ensure etcd or an etcd proxy is installed, and then
perform the following steps.

1.  Delete all configured OpenStack state, in particular any instances,
    routers, subnets and networks (in that order) created by the install
    process referenced above. You can do this using the web dashboard or
    at the command line.

    > **Tip**: The Admin and Project sections of the web dashboard both
    > have subsections for networks and routers. Some networks may
    > need to be deleted from the Admin section.
    {: .alert .alert-success}

    > **Important**: The {{site.prodname}} install will fail if incompatible state is
    > left around.
    {: .alert .alert-danger}

1.  Run `apt-get upgrade` and `apt-get dist-upgrade`. These commands
    bring in {{site.prodname}}-specific updates to the OpenStack packages and
    to `dnsmasq`.

1.  Edit the `/etc/neutron/neutron.conf` file. In the `[DEFAULT]` section, find
    the line beginning with `core_plugin`, and change it to read `core_plugin =
    calico`.  Also remove any existing setting for `service_plugins`.

1.  Install the `calico-control` package:

    ```
    apt-get install -y calico-control
    ```

1.  Restart the Neutron server process:

    ```
    service neutron-server restart
    ```

## Compute node install

On each compute node, perform the following steps:

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
    apt-get install -y neutron-common neutron-dhcp-agent nova-api-metadata
    ```

1.  Run `apt-get upgrade` and `apt-get dist-upgrade`. These commands
    bring in {{site.prodname}}-specific updates to the OpenStack packages and
    to `dnsmasq`.

1.  Modify `/etc/neutron/neutron.conf`.  In the `[oslo_concurrency]` section,
    ensure that the `lock_path` variable is uncommented and set as follows.

    ```
    # Directory to use for lock files. For security, the specified directory should
    # only be writable by the user running the processes that need locking.
    # Defaults to environment variable OSLO_LOCK_PATH. If external locks are used,
    # a lock path must be set.
    lock_path = $state_path/lock
    ```

    Add a `[calico]` section with the following content, where `<ip>` is the IP
    address of the etcd server.

    ```
    [calico]
    etcd_host = <ip>
    ```

1.  Install the {{site.prodname}} DHCP agent (which uses etcd, allowing
    it to scale to higher numbers of hosts) and disable the Neutron-provided
    one:

    ```
    service neutron-dhcp-agent stop
    echo manual | tee /etc/init/neutron-dhcp-agent.override
    apt-get install -y calico-dhcp-agent
    ```

1.  Install the `calico-compute` package:

    ```
    apt-get install -y calico-compute
    ```

    This step may prompt you to save your iptables rules to make them
    persistent on restart -- hit yes.

1.  Configure BIRD. By default {{site.prodname}} assumes that you will deploy a
    route reflector to avoid the need for a full BGP mesh. To this end, it
    includes configuration scripts to prepare a BIRD config file with a single
    peering to the route reflector. If that's correct for your network, you can
    run either or both of the following commands.

    For IPv4 connectivity between compute hosts:

    ```
    calico-gen-bird-conf.sh <compute_node_ip> <route_reflector_ip> <bgp_as_number>
    ```

    And/or for IPv6 connectivity between compute hosts:

    ```
    calico-gen-bird6-conf.sh <compute_node_ipv4> <compute_node_ipv6> <route_reflector_ipv6> <bgp_as_number>
    ```

    You also need to configure your route reflector to allow connections from
    the compute node as a route reflector client.  If you are using BIRD as a
    route reflector, follow the instructions
    [here]({{site.baseurl}}/{{page.version}}/usage/routereflector/bird-rr-config). If
    you are using another route reflector, refer to the appropriate
    instructions to configure a client connection.

    If you *are* configuring a full BGP mesh you need to handle the BGP
    configuration appropriately on each compute host. The scripts above can be
    used to generate a sample configuration for BIRD, by replacing the
    `<route_reflector_ip>` with the IP of one other compute host -- this will
    generate the configuration for a single peer connection, which you can
    duplicate and update for each compute host in your mesh.

    To maintain connectivity between VMs if BIRD crashes or is upgraded,
    configure BIRD graceful restart:

    -   Add `-R` to `BIRD_ARGS` in /etc/bird/envvars (you may need to
        uncomment this option).
    -   Edit the upstart jobs /etc/init/bird.conf and bird6.conf (if
        you're using IPv6), and add the following script to it.

        ```
        pre-stop script
        PID=`status bird | egrep -oi '([0-9]+)$' | head -n1`
        kill -9 $PID
        end script
        ```

1.  Create `/etc/calico/felix.cfg` with the following content, where `<ip>` is the IP
    address of the etcd server.

    ```
    [global]
    DatastoreType = etcdv3
    EtcdAddr = <ip>:2379
    ```

1.  Restart the Felix service.

    ```
    service calico-felix restart
    ```
