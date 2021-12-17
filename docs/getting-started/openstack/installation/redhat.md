---
title: Red Hat Enterprise Linux
description: Install Calico on OpenStack, Red Hat Enterprise Linux nodes.
canonical_url: '/getting-started/openstack/installation/redhat'
---

These instructions will take you through a first-time install of
{{site.prodname}}.  If you are upgrading an existing system, please see
[Upgrading {{site.prodname}} on OpenStack](../../../maintenance/openstack-upgrade)
instead.

There are two sections to the install: adding {{site.prodname}} to OpenStack
control nodes, and adding {{site.prodname}} to OpenStack compute nodes.  Follow
the [Common steps](#common-steps) on each node before moving on to the specific
instructions in the control and compute sections. If you want to create a
combined control and compute node, work through all three sections.

## Before you begin

- Ensure that you meet the [requirements](../requirements).
- Confirm that you have SSH access to and root privileges on one or more Red Hat
  Enterprise Linux (RHEL) hosts.
- Make sure you have working DNS between the RHEL hosts (use `/etc/hosts` if you
  don't have DNS on your network).
- {% include open-new-window.html text='Install OpenStack with Neutron and ML2 networking' url='http://docs.openstack.org' %}
  on the RHEL hosts.

## Common steps

Some steps need to be taken on all machines being installed with {{site.prodname}}.
These steps are detailed in this section.

{% include ppa_repo_name %}

1.  {% include open-new-window.html text='Add the EPEL repository' url='https://fedoraproject.org/wiki/EPEL' %}. You may
    have already added this to install OpenStack.

1.  Configure the {{site.prodname}} repository:

    ```bash
    cat > /etc/yum.repos.d/calico.repo <<EOF
    [calico]
    name=Calico Repository
    baseurl=https://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/
    enabled=1
    skip_if_unavailable=0
    gpgcheck=1
    gpgkey=https://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/key
    priority=97
    EOF
    ```

1.  Install the `etcd3-gateway` Python package.  A current copy of that code is
    needed by {{site.prodname}}'s OpenStack driver and DHCP agent, so you
    should install it with `pip3`.

    ```
    yum install python3-pip
    pip3 install git+https://github.com/dims/etcd3-gateway.git@5a3157a122368c2314c7a961f61722e47355f981
    ```

1.  Edit `/etc/neutron/neutron.conf`.  Add a `[calico]` section with
    the following content, where `<ip>` is the IP address of the etcd
    server.

    ```
    [calico]
    etcd_host = <ip>
    ```

## Control node install

On each control node, perform the following steps:

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

1.  Edit `/etc/neutron/neutron.conf`. In the `[DEFAULT]` section, find
    the line beginning with `core_plugin`, and change it to read `core_plugin =
    calico`.  Also remove any existing setting for `service_plugins`.

1.  Install the `calico-control` package:

    ```
    yum install -y calico-control
    ```

1.  Restart the neutron server process:

    ```
    service neutron-server restart
    ```

## Compute node install

On each compute node, perform the following steps:

1.  Open `/etc/nova/nova.conf` and remove the line from the `[DEFAULT]`
    section that reads:

    ```conf
    linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver
    ```

    Remove the lines from the `[neutron]` section setting
    `service_neutron_metadata_proxy` or `service_metadata_proxy` to
    `True`, if there are any. Additionally, if there is a line setting
    `metadata_proxy_shared_secret`, comment that line out as well.

    Restart nova compute.

    ```bash
    service openstack-nova-compute restart
    ```

    If this node is also a controller, additionally restart nova-api.

    ```bash
    service openstack-nova-api restart
    ```

1.  If they're running, stop the Open vSwitch services.

    ```bash
    service neutron-openvswitch-agent stop
    service openvswitch stop
    ```

    Then, prevent the services running if you reboot.

    ```bash
    chkconfig openvswitch off
    chkconfig neutron-openvswitch-agent off
    ```

    Then, on your control node, run the following command to find the
    agents that you just stopped.

    ```
    neutron agent-list
    ```

    For each agent, delete them with the following command on your
    control node, replacing `<agent-id>` with the ID of the agent.

    ```
    neutron agent-delete <agent-id>
    ```

1.  Install Neutron infrastructure code on the compute host.

    ```
    yum install -y openstack-neutron
    ```

1.  Edit `/etc/neutron/neutron.conf`.  In the `[oslo_concurrency]` section,
    ensure that the `lock_path` variable is uncommented and set as follows.

    ```
    # Directory to use for lock files. For security, the specified directory should
    # only be writable by the user running the processes that need locking.
    # Defaults to environment variable OSLO_LOCK_PATH. If external locks are used,
    # a lock path must be set.
    lock_path = $state_path/lock
    ```
    {: .no-select-button}

1.  Stop and disable the Neutron DHCP agent, and install the
    {{site.prodname}} DHCP agent (which uses etcd, allowing it to scale to higher
    numbers of hosts).

    ```
    service neutron-dhcp-agent stop
    chkconfig neutron-dhcp-agent off
    yum install -y calico-dhcp-agent
    ```

1.  Stop and disable any other routing/bridging agents such as the L3
    routing agent or the Linux bridging agent. These conflict
    with {{site.prodname}}.

    ```bash
    service neutron-l3-agent stop
    chkconfig neutron-l3-agent off
    ```

    Repeat for bridging agent and any others.

1.  If this node is not a controller, install and start the Nova
    Metadata API. This step is not required on combined compute and
    controller nodes.

    ```bash
    yum install -y openstack-nova-api
    service openstack-nova-metadata-api restart
    chkconfig openstack-nova-metadata-api on
    ```

1.  Install the BIRD BGP client.

    ```bash
    yum install -y bird bird6
    ```

1.  Install the `calico-compute` package.

    ```bash
    yum install -y calico-compute
    ```

1.  Configure BIRD. By default {{site.prodname}} assumes that you will deploy a
    route reflector to avoid the need for a full BGP mesh. To this end, it
    includes configuration scripts to prepare a BIRD config file with a single
    peering to the route reflector. If that's correct for your network, you can
    run either or both of the following commands.

    For IPv4 connectivity between compute hosts:

    ```bash
    calico-gen-bird-conf.sh <compute_node_ip> <route_reflector_ip> <bgp_as_number>
    ```

    And/or for IPv6 connectivity between compute hosts:

    ```bash
    calico-gen-bird6-conf.sh <compute_node_ipv4> <compute_node_ipv6> <route_reflector_ipv6> <bgp_as_number>
    ```

    You will also need to [configure your route reflector to allow
    connections from the compute node as a route reflector
    client](../../../networking/bgp).

    If you *are* configuring a full BGP mesh you need to handle the BGP
    configuration appropriately on each compute host. The scripts above can be
    used to generate a sample configuration for BIRD, by replacing the
    `<route_reflector_ip>` with the IP of one other compute host—this will
    generate the configuration for a single peer connection, which you can
    duplicate and update for each compute host in your mesh.

    To maintain connectivity between VMs if BIRD crashes or is upgraded,
    configure BIRD graceful restart. Edit the systemd unit file
    /usr/lib/systemd/system/bird.service (and bird6.service for IPv6):

    -   Add `-R` to the end of the `ExecStart` line.
    -   Add `KillSignal=SIGKILL` as a new line in the `[Service]` section.
    -   Run `systemctl daemon-reload` to tell systemd to reread that file.

    Ensure that BIRD (and/or BIRD 6 for IPv6) is running and starts on
    reboot.

    ```bash
    service bird restart
    service bird6 restart
    chkconfig bird on
    chkconfig bird6 on
    ```

1.  Create `/etc/calico/felix.cfg` with the following content, where `<ip>` is the IP
    address of the etcd server.

    ```conf
    [global]
    DatastoreType = etcdv3
    EtcdAddr = <ip>:2379
    ```

1.  Restart the Felix service.

    ```
    service calico-felix restart
    ```

{% include content/openstack-etcd-auth.md %}
