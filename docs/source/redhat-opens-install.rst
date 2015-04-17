.. # Copyright (c) Metaswitch Networks 2015. All rights reserved.
   #
   #    Licensed under the Apache License, Version 2.0 (the "License"); you may
   #    not use this file except in compliance with the License. You may obtain
   #    a copy of the License at
   #
   #         http://www.apache.org/licenses/LICENSE-2.0
   #
   #    Unless required by applicable law or agreed to in writing, software
   #    distributed under the License is distributed on an "AS IS" BASIS,
   #    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
   #    implied. See the License for the specific language governing
   #    permissions and limitations under the License.

Red Hat Enterprise Linux 6.5/7 Packaged Install Instructions
============================================================

.. note:: Following the change to use etcd instead of message queues to
          communicate between components, this document may now contain out of
          date information. We will remedy this in the near future.

The instructions come in two sections: one for installing control nodes,
and one for installing compute nodes. Before moving on to those
sections, make sure you follow the **Common Steps** section, and if you
want to create a combined controller and compute node, work through all
three sections.

Prerequisites
-------------

Before starting this you will need the following:

-  One or more machines running RHEL 6.5 or 7:

   - For RHEL 6.5, these machines should have OpenStack Icehouse installed on
     them.
   - For RHEL 7, these machines should have OpenStack Juno installed on them.

-  SSH access to these machines.
-  Working DNS between these machines (use ``/etc/hosts`` if you don't
   have DNS on your network).

Common Steps
------------

Some steps need to be taken on all machines being installed with Calico.
These steps are detailed here.

Install OpenStack Icehouse/Juno
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you haven't already done so, install Icehouse (RHEL 6.5) or Juno (RHEL 7)
with Neutron and ML2 networking. Instructions for installing OpenStack on RHEL
can be found `here <http://openstack.redhat.com/Main_Page>`__.

Configure YUM repositories
~~~~~~~~~~~~~~~~~~~~~~~~~~

As well as the repositories for OpenStack and EPEL
(https://fedoraproject.org/wiki/EPEL) - which you will have already
configured as part of the previous step - you will need to configure the
repository for Calico.

For RHEL 7::

    cat > /etc/yum.repos.d/calico.repo <<EOF
    [calico]
    name=Calico Repository
    baseurl=http://binaries.projectcalico.org/rpm/
    enabled=1
    skip_if_unavailable=0
    gpgcheck=1
    gpgkey=http://binaries.projectcalico.org/rpm/key
    priority=97
    EOF

For RHEL 6.5::

    cat > /etc/yum.repos.d/calico.repo <<EOF
    [calico]
    name=Calico Repository
    baseurl=http://binaries.projectcalico.org/rhel6/
    enabled=1
    skip_if_unavailable=0
    gpgcheck=1
    gpgkey=http://binaries.projectcalico.org/rpm/key
    priority=97
    EOF

Note: The priority setting in ``calico.repo`` is needed so that the
Calico repository can install Calico-enhanced versions of some of the
OpenStack Nova and Neutron packages.

Control Node Install
--------------------

On a control node, perform the following steps:

1. Delete all configured OpenStack state, in particular any instances,
   routers, and networks (in that order) created by the install process
   referenced above. You can do this using the web dashboard or at the
   command line. The Calico install will fail if incompatible state is
   left around.

2. Run ``yum update``. This will bring in Calico-specific updates to the
   OpenStack packages and to ``dnsmasq``.

3. Install the ``calico-control`` package:

   ::

       yum install calico-control

4. Edit the ``/etc/neutron/plugins/ml2/ml2_conf.ini`` file:

   -  Find the ``type_drivers`` setting and change it to read
      ``type_drivers = local, flat``.
   -  Find the ``tenant_network_types`` setting and change it to read
      ``tenant_network_types = local``.
   -  Find the ``mechanism_drivers`` setting and change it to read
      ``mechanism_drivers = calico``.

5. Edit the ``/etc/neutron/neutron.conf`` file:

   -  Find the line for the ``dhcp_agents_per_network`` setting,
      uncomment it, and set its value to the number of compute nodes
      that you will have (or any number larger than that). This allows a
      DHCP agent to run on every compute node, which Calico requires
      because the networks on different compute nodes are not bridged
      together.
   -  Find the lines for ``api_workers`` and ``rpc_workers``, uncomment
      them and set them both to 0.

6. Restart the neutron server process:
   ``service neutron-server restart``.

7. Create the ``/etc/calico/acl_manager.cfg`` file by copying the
   ``/etc/calico/acl_manager.cfg.example`` file and edit it:

   -  Change the ``PluginAddress`` to the host name or IP address of the
      controller node. Then restart the ACL manager service with:

      - On Red Hat 6.5, ``initctl start calico-acl-manager``
      - On Red Hat 7, ``systemctl restart calico-acl-manager``.

Compute Node Install
--------------------

On a compute node, perform the following steps:

1. Make the changes to SELinux and QEMU config that are described in `this
   libvirt Wiki page <http://wiki.libvirt.org/page/Guest_won%27t_start_-_warning:_could_not_open_/dev/net/tun_%28%27generic_ethernet%27_interface%29>`__,
   to allow VM interfaces with ``type='ethernet'``.

   ::

       setenforce permissive

   Edit ``/etc/selinux/config`` and change the ``SELINUX=`` line to the
   following:

   ::

           SELINUX=permissive

   In ``/etc/libvirt/qemu.conf``, add or edit the following four options
   (in particular note the ``/dev/net/tun`` in ``cgroup_device_acl``):

   ::

           clear_emulator_capabilities = 0
           user = "root"
           group = "root"
           cgroup_device_acl = [
                "/dev/null", "/dev/full", "/dev/zero",
                "/dev/random", "/dev/urandom",
                "/dev/ptmx", "/dev/kvm", "/dev/kqemu",
                "/dev/rtc", "/dev/hpet", "/dev/net/tun",
           ]

   Then restart libvirt to pick up the changes:

   ::

           service libvirtd restart

2. Open ``/etc/nova/nova.conf`` and remove the line that reads:

   ::

       linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver

   Remove the line setting ``service_neutron_metadata_proxy`` or
   ``service_metadata_proxy`` to ``True``, if there is one.

   Restart nova compute.

   ::

           service openstack-nova-compute restart

3. If they're running, stop the Open vSwitch services:

   ::

       service neutron-openvswitch-agent stop
       service openvswitch stop

   Then, prevent the services running if you reboot:

   ::

           chkconfig openvswitch off
           chkconfig neutron-openvswitch-agent off

4. Run ``yum update``. This will bring in Calico-specific updates to the
   OpenStack packages and to ``dnsmasq``.

5. Install build dependencies:

   ::

       yum groupinstall 'Development Tools'

6. Install and configure the DHCP agent on the compute host:

   ::

       yum install openstack-neutron

   Open ``/etc/neutron/dhcp_agent.ini``. In the ``[DEFAULT]`` section, add
   the following line (removing any existing ``interface_driver =`` line):

   ::

           interface_driver = neutron.agent.linux.interface.RoutedInterfaceDriver

7.  Restart and enable the DHCP agent, and stop and disable the L3
    agent.

    ::

        service neutron-dhcp-agent restart
        chkconfig neutron-dhcp-agent on
        service neutron-l3-agent stop
        chkconfig neutron-l3-agent off

8.  If this node is not a controller, install and start the Nova
    Metadata API. This step is not required on combined compute and
    controller nodes.

    ::

        yum install openstack-nova-api
        service openstack-nova-metadata-api restart
        chkconfig openstack-nova-metadata-api on

9.  For RHEL 7, install the BIRD BGP client from EPEL:
    ``yum install -y bird bird6``. Then, go on to the next step.

    For RHEL 6.5, BIRD needs to be built from source and installed manually.

    First, download the source and build BIRD.

    ::

        yum install -y flex bison readline-devel ncurses-devel gcc wget
        wget ftp://bird.network.cz/pub/bird/bird-1.4.5.tar.gz
        tar xzvf bird-1.4.5.tar.gz
        cd bird-1.4.5
        ./configure
        make
        make install

    Now, create the upstart job file for BIRD by putting the following in
    ``/etc/init/bird.conf``

    ::

        description "BIRD Internet Routing Daemon"
        start on runlevel [2345]
        stop on runlevel [016]
        respawn
        pre-start script
        /usr/local/sbin/bird -p -c /etc/bird/bird.conf
        end script
        script
        /usr/local/sbin/bird -f -c /etc/bird/bird.conf
        end script

10. Install the ``calico-compute`` package:

    ::

        yum install calico-compute

11. Configure BIRD. Calico includes useful configuration scripts that
    will create BIRD config files for simple topologies -- either a
    peering between a single pair of compute nodes, or to a route
    reflector (to avoid the need for a full BGP mesh in networks with
    more than two compute nodes). If your topology is more complex, please
    consult the relevant documentation for your chosen BGP stack or ask
    the mailing list if you have questions about how BGP relates to
    Calico.

    For IPv4 connectivity between compute hosts:

    ::

        /usr/bin/calico-gen-bird-conf.sh <compute_node_ipv4> <peer_ipv4> <bgp_as_number>

    And/or for IPv6 connectivity between compute hosts:

    ::

        /usr/bin/calico-gen-bird6-conf.sh <compute_node_ipv4> <compute_node_ipv6> <peer_ipv6> <bgp_as_number>

    ``<compute_node_ipv4>`` and ``<compute_node_ipv6>`` are the IPv4/6
    addresses of the compute host, used as next hops and router ids.

    ``<peer_ipv4>`` and ``<peer_ipv6>`` are the IP address of your
    single other compute node, or the route reflector as described
    earlier.

    ``<bgp_as_number>`` is the BGP `AS
    number <http://en.wikipedia.org/wiki/Autonomous_System_%28Internet%29>`__.
    Unless your deployment needs to peer with other BGP routers, this
    can be chosen arbitrarily.

    For RHEL 6.5, ignore any ``bird: unrecognized service`` error -- we'll
    restart BIRD later anyway.

   Note that you'll also need to configure your route reflector to allow
   connections from the compute node as a route reflector client. This
   configuration is outside the scope of this install document.

   Ensure BIRD (and/or BIRD 6 for IPv6) is running and starts on reboot:

   - For RHEL 7:

     ::

         service bird restart
         service bird6 restart
         chkconfig bird on
         chkconfig bird6 on

   - For RHEL 6.5:

     ::

         initctl start bird

12. Create the ``/etc/calico/felix.cfg`` file by copying
    ``/etc/calico/felix.cfg.example`` and edit it:

    -  Change the ``PluginAddress`` and ``ACLAddress`` settings to the
       host name or IP address of the controller node.
    -  Restart the Felix service:

       - on RHEL 6.5, run ``initctl start calico-felix``.
       - on RHEL 7, run ``systemctl restart calico-felix``.

Next Steps
----------

Now you've installed Calico, follow :ref:`opens-install-inst-next-steps` for
details on how to configure networks and use your new deployment.
