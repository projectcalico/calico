---
title: Red Hat Enterprise Linux 7 Packaged Install Instructions
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/openstack/installation/redhat'
---

For this version of Calico, with OpenStack on RHEL 7 or CentOS 7, we recommend
using OpenStack Liberty or later.

> **NOTE**
>
> On RHEL/CentOS 7.3, with Mitaka or earlier, there is a Nova
> [bug](https://bugs.launchpad.net/nova/+bug/1649527) that breaks Calico
> operation.  You can avoid this bug by:
>
> - using Newton or later (recommended)
>
> - or manually [patching](https://review.openstack.org/#/c/425637/) your Nova
>   install on each compute node.

These instructions will take you through a first-time install of Calico.  If
you are upgrading an existing system, please see the [Calico on OpenStack
upgrade]({{site.baseurl}}/{{page.version}}/getting-started/openstack/upgrade)
document instead for upgrade instructions.

There are three sections to the install: installing etcd, upgrading
control nodes to use Calico, and upgrading compute nodes to use Calico.
Follow the **Common Steps** on each node before moving on to the
specific instructions in the control and compute sections. If you want
to create a combined control and compute node, work through all three
sections.

> **WARNING**
>
> Following the upgrade to use etcd as a data store, Calico
> currently only supports RHEL 7 and above. If support on RHEL 6.x
> or other versions of Linux is important to you, then please [let
> us know](https://www.projectcalico.org/contact/).
>

## Prerequisites

Before starting this you will need the following:

-   One or more machines running RHEL 7, with OpenStack installed.
-   SSH access to these machines.
-   Working DNS between these machines (use `/etc/hosts` if you don't
    have DNS on your network).

## Common Steps

Some steps need to be taken on all machines being installed with Calico.
These steps are detailed in this section.

### Install OpenStack

If you haven't already done so, install Openstack with Neutron and ML2
networking.

### Configure YUM repositories

{% include ppa_repo_name %}

Add the EPEL repository -- see <https://fedoraproject.org/wiki/EPEL>.
You may have already added this to install OpenStack.

Configure the Calico repository:

```
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

## Etcd Install

Calico requires an etcd database to operate - this may be installed on a
single machine or as a cluster.

These instructions cover installing a single node etcd database. You may
wish to co-locate this with your control node. If you want to install a
cluster, please get in touch with us and we'll be happy to help you
through the process.

1.  Install and configure etcd.
    -   Download, unpack, and install the binary:

        ```
            curl -L  https://github.com/coreos/etcd/releases/download/v2.0.11/etcd-v2.0.11-linux-amd64.tar.gz -o etcd-v2.0.11-linux-amd64.tar.gz
            tar xvf etcd-v2.0.11-linux-amd64.tar.gz
            cd etcd-v2.0.11-linux-amd64
            mv etcd* /usr/local/bin/
        ```

        > **WARNING**
        >
        > We've seen certificate errors downloading etcd - you may need
        > to add `--insecure` to the curl command to ignore this.
        >

    -   Create an etcd user:

        ```
            adduser -s /sbin/nologin -d /var/lib/etcd/ etcd
            chmod 700 /var/lib/etcd/
        ```

    -   Add the following line to the bottom of `/etc/fstab`. This will
        mount a ramdisk for etcd at startup:

        ```
            tmpfs /var/lib/etcd tmpfs nodev,nosuid,noexec,nodiratime,size=512M 0 0
        ```

    -   Run `mount -a` to mount it now.
    -   Get etcd running by providing an init file.

        Place the following in `/etc/sysconfig/etcd`, replacing
        `<hostname>` and `<public_ip>` with their appropriate values for
        the machine.

        ```
            ETCD_DATA_DIR=/var/lib/etcd
            ETCD_NAME=<hostname>
            ETCD_ADVERTISE_CLIENT_URLS="http://<public_ip>:2379,http://<public_ip>:4001"
            ETCD_LISTEN_CLIENT_URLS="http://0.0.0.0:2379,http://0.0.0.0:4001"
            ETCD_LISTEN_PEER_URLS="http://0.0.0.0:2380"
            ETCD_INITIAL_ADVERTISE_PEER_URLS="http://<public_ip>:2380"
            ETCD_INITIAL_CLUSTER="<hostname>=http://<public_ip>:2380"
            ETCD_INITIAL_CLUSTER_STATE=new
        ```

        Check the `uuidgen` tool is installed (the output should change
        each time):

        ```
            # uuidgen
            11f92f19-cb5a-476f-879f-5efc34033b8b
        ```

        If it is not installed, run `yum install util-linux` to
        install it.

        Place the following in `/usr/local/bin/start-etcd`:

        ```
            #!/bin/sh
            export ETCD_INITIAL_CLUSTER_TOKEN=`uuidgen`
            exec /usr/local/bin/etcd
        ```

        Then run `chmod +x /usr/local/bin/start-etcd` to make that
        file executable.

        You then need to add the following file to
        `/usr/lib/systemd/system/etcd.service`:

        ```
            [Unit]
            Description=Etcd
            After=syslog.target network.target

            [Service]
            User=root
            ExecStart=/usr/local/bin/start-etcd
            EnvironmentFile=-/etc/sysconfig/etcd
            KillMode=process
            Restart=always

            [Install]
            WantedBy=multi-user.target
        ```

2.  Launch etcd and set it to restart after a reboot:

    ```
        systemctl start etcd
        systemctl enable etcd
    ```

## Etcd Proxy Install

Install an etcd proxy on every node running OpenStack services that
isn't running the etcd database itself (both control and compute nodes).

1.  Install and configure etcd as an etcd proxy.

    -   Download, unpack, and install the binary:

    ```
        curl -L  https://github.com/coreos/etcd/releases/download/v2.0.11/etcd-v2.0.11-linux-amd64.tar.gz -o etcd-v2.0.11-linux-amd64.tar.gz
        tar xvf etcd-v2.0.11-linux-amd64.tar.gz
        cd etcd-v2.0.11-linux-amd64
        mv etcd* /usr/local/bin/
    ```

    > **WARNING**
    >
    > We've seen certificate errors downloading etcd - you may need
    > to add `--insecure` to the curl command to ignore this.
    >

    -   Create an etcd user:

    ```
           adduser -s /sbin/nologin -d /var/lib/etcd/ etcd
           chmod 700 /var/lib/etcd/
    ```

    -   Get etcd running by providing an init file.

        Place the following in `/etc/sysconfig/etcd`, replacing
        `<etcd_hostname>` and `<etcd_ip>` with the values you used in
        the [etcd install](#etcd-install) section.

    ```
            ETCD_PROXY=on
            ETCD_DATA_DIR=/var/lib/etcd
            ETCD_INITIAL_CLUSTER="<etcd_hostname>=http://<etcd_ip>:2380"
    ```

        You then need to add the following file to `/usr/lib/systemd/system/etcd.service`

    ```
            [Unit]
            Description=Etcd
            After=syslog.target network.target

            [Service]
            User=root
            ExecStart=/usr/local/bin/etcd
            EnvironmentFile=-/etc/sysconfig/etcd
            KillMode=process
            Restart=always

            [Install]
            WantedBy=multi-user.target
    ```

2.  Launch etcd and set it to restart after a reboot:

    ```
        systemctl start etcd
        systemctl enable etcd
    ```

## Control Node Install

On each control node, perform the following steps:

1.  Delete all configured OpenStack state, in particular any instances,
    routers, subnets and networks (in that order) created by the install
    process referenced above. You can do this using the web dashboard or
    at the command line.

    > **HINT**
    >
    > The Admin and Project sections of the web dashboard both
    > have subsections for networks and routers. Some networks may
    > need to be deleted from the Admin section.
    >

    > **WARNING**
    >
    > The Calico install will fail if incompatible state is
    > left around.
    >

3.  Edit the `/etc/neutron/neutron.conf` file. In the `[DEFAULT]`
    section:
    -   Find the line beginning with `core_plugin`, and change it to
        read `core_plugin = calico`.

4.  Install the `calico-control` package:

    ```
        yum install calico-control
    ```

5.  Restart the neutron server process:

    ```
        service neutron-server restart
    ```

## Compute Node Install

On each compute node, perform the following steps:

1.  Make changes to SELinux and QEMU config to allow VM interfaces with
    `type='ethernet'` ([this libvirt Wiki
    page](https://web.archive.org/web/20160226213437/http://wiki.libvirt.org/page/Guest_won't_start_-_warning:_could_not_open_/dev/net/tun_('generic_ethernet'_interface))
    explains why these changes are required):

    ```
        setenforce permissive
    ```

    Edit `/etc/selinux/config` and change the `SELINUX=` line to the
    following:

    ```
        SELINUX=permissive
    ```

    In `/etc/libvirt/qemu.conf`, add or edit the following four options:

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

    > **NOTE**
    >
    > The `cgroup_device_acl` entry is subtly different to the
    >
    > :   default. It now contains `/dev/net/tun`.
    >

    Then restart libvirt to pick up the changes:

    ```
        service libvirtd restart
    ```

2.  Open `/etc/nova/nova.conf` and remove the line from the `[DEFAULT]`
    section that reads:

    ```
        linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver
    ```

    Remove the lines from the \[neutron\] section setting
    `service_neutron_metadata_proxy` or `service_metadata_proxy` to
    `True`, if there are any. Additionally, if there is a line setting
    `metadata_proxy_shared_secret`, comment that line out as well.

    Restart nova compute.

    ```
        service openstack-nova-compute restart
    ```

    If this node is also a controller, additionally restart nova-api:

    ```
        service openstack-nova-api restart
    ```

3.  If they're running, stop the Open vSwitch services:

    ```
        service neutron-openvswitch-agent stop
        service openvswitch stop
    ```

    Then, prevent the services running if you reboot:

    ```
        chkconfig openvswitch off
        chkconfig neutron-openvswitch-agent off
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

5.  Install Neutron infrastructure code on the compute host:

    ```
        yum install openstack-neutron
    ```

6.  Modify `/etc/neutron/neutron.conf`.  In the `[oslo_concurrency]` section,
    ensure that the `lock_path` variable is uncommented and set as follows:

    ```
        # Directory to use for lock files. For security, the specified directory should
        # only be writable by the user running the processes that need locking.
        # Defaults to environment variable OSLO_LOCK_PATH. If external locks are used,
        # a lock path must be set.
        lock_path = $state_path/lock
    ```

    Then, stop and disable the Neutron DHCP agent, and install the
    Calico DHCP agent (which uses etcd, allowing it to scale to higher
    numbers of hosts):

    ```
        service neutron-dhcp-agent stop
        chkconfig neutron-dhcp-agent off
        yum install calico-dhcp-agent
    ```

7.  Stop and disable any other routing/bridging agents such as the L3
    routing agent or the Linux bridging agent. These conflict
    with Calico.

    ```
        service neutron-l3-agent stop
        chkconfig neutron-l3-agent off
        ... repeat for bridging agent and any others ...
    ```

8.  If this node is not a controller, install and start the Nova
    Metadata API. This step is not required on combined compute and
    controller nodes.

    ```
        yum install openstack-nova-api
        service openstack-nova-metadata-api restart
        chkconfig openstack-nova-metadata-api on
    ```

9.  Install the BIRD BGP client from EPEL:

    ```
        yum install -y bird bird6
    ```

10. Install the `calico-compute` package:

    ```
        yum install calico-compute
    ```

11. Configure BIRD. By default Calico assumes that you'll be deploying a
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
    in [this document]({{site.baseurl}}/{{page.version}}/usage/routereflector/bird-rr-config). If you are using another route reflector, refer
    to the appropriate instructions to configure a client connection.

    If you *are* configuring a full BGP mesh you'll need to handle the
    BGP configuration appropriately on each compute host. The scripts
    above can be used to generate a sample configuration for BIRD, by
    replacing the `<route_reflector_ip>` with the IP of one other
    compute host -- this will generate the configuration for a single
    peer connection, which you can duplicate and update for each compute
    host in your mesh.

    To maintain connectivity between VMs if BIRD crashes or is upgraded,
    configure BIRD graceful restart. Edit the systemd unit file
    /usr/lib/systemd/system/bird.service (and bird6.service for IPv6):

    -   Add -R to the end of the ExecStart line.
    -   Add KillSignal=SIGKILL as a new line in the \[Service\] section.

    Ensure BIRD (and/or BIRD 6 for IPv6) is running and starts on
    reboot:

    ```
        service bird restart
        service bird6 restart
        chkconfig bird on
        chkconfig bird6 on
    ```

12. Create the `/etc/calico/felix.cfg` file by copying
    `/etc/calico/felix.cfg.example`. Ordinarily the default values
    should be used, but see [Configuration]({{site.baseurl}}/{{page.version}}/getting-started/openstack/) for more details.

13. Restart the Felix service:

    ```
        systemctl restart calico-felix
    ```
