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

Ubuntu 14.04 Packaged Install Instructions
==========================================

These instructions will take you through installing Calico using the
latest packages on a system running Ubuntu 14.04 with either OpenStack
Icehouse or Juno.

The instructions come in two sections: one for installing control nodes,
and one for installing compute nodes. Before moving on to those
sections, make sure you follow the **Common Steps** section.

Prerequisites
-------------

Before starting this you will need the following:

-  A machine running Ubuntu 14.04.
-  SSH access to the machine.

Common Steps
------------

Some steps need to be taken on all machines being installed with Calico.
These steps are detailed here.

Install OpenStack Icehouse or Juno
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you haven't already done so, you should install OpenStack with
Neutron and ML2 networking. Instructions for installing OpenStack can be
found here -
`Icehouse <http://docs.openstack.org/icehouse/install-guide/install/apt/content/ch_preface.html>`__
`Juno <http://docs.openstack.org/juno/install-guide/install/apt/content/ch_preface.html>`__.

Configuring the APT software sources
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The machines need to be configured such that APT can get access to the
Calico packages. This step differs depending on whether you're using
Icehouse or Juno.

Icehouse
^^^^^^^^

Add the Calico PPA.

::

    sudo apt-add-repository ppa:project-calico/icehouse


Edit ``/etc/apt/preferences`` to add the following lines, whose effect
is to prefer Calico-provided packages for Nova and Neutron even if later
versions of those packages are released by Ubuntu.

::

    Package: *
    Pin: release o=LP-PPA-project-calico-*
    Pin-Priority: 1001

Juno
^^^^

Add the Calico PPA.

::

    sudo add-apt-repository ppa:project-calico/juno

Edit ``/etc/apt/preferences`` to add the following lines, whose effect
is to prefer Calico-provided packages for Nova and Neutron even if later
versions of those packages are released by Ubuntu.

::

    Package: *
    Pin: release -o=LP-PPA-project-calico-*
    Pin-Priority: 1001

Common
^^^^^^

You will also need to add the official
`BIRD <http://bird.network.cz/>`__ PPA. This PPA contains fixes to BIRD
that are not yet available in Ubuntu 14.04. To add the PPA, run:

::

    sudo add-apt-repository ppa:cz.nic-labs/bird

Once that's done, update your package manager on each machine:

::

    sudo apt-get update

Control Node Install
--------------------

On a control node, perform the following steps:

1. Run ``apt-get upgrade`` and ``apt-get dist-upgrade``. These commands
   will bring in Calico-specific updates to the OpenStack packages and
   to ``dnsmasq``.

2. Install the ``etcd`` packages:

   ::

       sudo apt-get install etcd python-etcd

3. Stop etcd service
   ::

       sudo service etcd stop

4. Delete any existing etcd database
   ::

       sudo rm -rf /var/lib/etcd/*

5. Mount a ramdisk at /var/lib/etcd:
   ::

    sudo mount -t tmpfs -o size=512m tmpfs /var/lib/etcd

6. add the following to the bottom of ``/etc/fstab`` so that the ramdisk gets
   reinstated at boot time:

   ::

    tmpfs /var/lib/etcd-rd tmpfs nodev,nosuid,noexec,nodiratime,size=512M 0 0


5. Edit ``/etc/init/etcd.conf``:

   - Find the line which begins ``exec /usr/bin/etcd`` and edit it,
     substituting for ``<controller_fqdn>``, ``<controller_ip>``, and
     ``<cluster_token>`` appropriately. Each time you create a new etcd cluster
     you should use a new cluster_token, as this is checked by Calico
     components to check whether etcd has moved.

   ::

       exec /usr/bin/etcd -name="<controller_fqdn>"                                                         \
                          -advertise-client-urls="http://<controller_ip>:2379,http://<controller_ip>:4001"  \
                          -listen-client-urls="http://0.0.0.0:2379,http://0.0.0.0:4001"                     \
                          -listen-peer-urls "http://0.0.0.0:2380"                                           \
                          -initial-advertise-peer-urls "http://<controller_ip>:2380"                        \
                          -initial-cluster-token "<cluster_token>"                                          \
                          -initial-cluster "<controller_fqdn>=http://<controller_ip>:2380"                  \
                          -initial-cluster-state "new"

6. Start etcd service
   ::

       sudo service etcd start


7. Install the ``calico-control`` package:

   ::

       sudo apt-get install calico-control

8. Edit the ``/etc/neutron/plugins/ml2/ml2_conf.ini`` file:

   -  Find the line beginning with ``type_drivers``, and change it to
      read ``type_drivers = local, flat``.
   -  Find the line beginning with ``mechanism_drivers``, and change it
      to read ``mechanism_drivers = calico``.
   -  Find the line beginning with ``tenant_network_types``, and change
      it to read ``tenant_network_types = local``.

9. Edit the ``/etc/neutron/neutron.conf`` file:

   -  Find the line for the ``dhcp_agents_per_network`` setting,
      uncomment it, and set its value to the number of compute nodes
      that you will have (or any number larger than that). This allows a
      DHCP agent to run on every compute node, which Calico requires
      because the networks on different compute nodes are not bridged
      together.
   -  Find the line for the ``api_workers`` setting, uncomment it and
      set its value to 0.
   -  Find the line for the ``rpc_workers`` setting, uncomment it and
      set its value to 0.

10. Restart the neutron server process:

   ::

        sudo service neutron-server restart

Compute Node Install
--------------------

On a compute node, perform the following steps:

1. Make the changes to SELinux and QEMU config that are described in
   `this libvirt Wiki page <http://wiki.libvirt.org/page/Guest_won't_start_-_warning:_could_not_open_/dev/net/tun_('generic_ethernet'_interface)>`__,
   to allow VM interfaces with ``type='ethernet'``.

   Disable SELinux if it's running. SELinux isn't installed by default
   on Ubuntu - you can check its status by running ``sestatus``. If this
   is installed and the current mode is ``enforcing``, then disable it
   by running ``setenforce permissive`` and setting
   ``SELINUX=permissive`` in ``/etc/selinux/config``.

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

       sudo service libvirt-bin restart

2. Open ``/etc/nova/nova.conf`` and remove the line that reads:

   ::

       linuxnet_interface_driver = nova.network.linux_net.LinuxOVSInterfaceDriver

   Remove the line setting ``service_neutron_metadata_proxy`` or
   ``service_metadata_proxy`` to ``True``, if there is one.

   Restart nova compute.

   ::

       sudo service nova-compute restart

3. If they're running, stop the Open vSwitch services:

   ::

       sudo service openvswitch-switch stop
       sudo service neutron-plugin-openvswitch-agent stop

   Then, prevent the services running if you reboot:

   ::

           sudo sh -c "echo 'manual' > /etc/init/openvswitch-switch.override"
           sudo sh -c "echo 'manual' > /etc/init/openvswitch-force-reload-kmod.override"
           sudo sh -c "echo 'manual' > /etc/init/neutron-plugin-openvswitch-agent.override"

4. Install some extra packages.

   ::

       sudo apt-get install neutron-common neutron-dhcp-agent nova-api-metadata

5. Open ``/etc/neutron/dhcp_agent.ini`` in your preferred text editor.
   In the ``[DEFAULT]`` section, add the following line:

   ::

       interface_driver = neutron.agent.linux.interface.RoutedInterfaceDriver

   Now restart the DHCP agent:

   ::

       sudo service neutron-dhcp-agent restart

6. Run ``apt-get upgrade`` and ``apt-get dist-upgrade``. These commands
   will bring in Calico-specific updates to the OpenStack packages and
   to ``dnsmasq``.

7. Install the ``etcd``, ``python-etcd`` packages:

   ::

       sudo apt-get install etcd python-etcd

8. Stop etcd service
   ::

       sudo service etcd stop

9. Delete any existing etcd database
   ::

        sudo rm -rf /var/lib/etcd/*

10. Edit ``/etc/init/etcd.conf``:

   - Find the line which begins ``exec /usr/bin/etcd`` and edit it,
     substituting for ``<controller_fqdn>`` and ``<controller_ip>``
     appropriately:

   ::

       exec /usr/bin/etcd -proxy on                                                         \
                          -listen-client-urls http://127.0.0.1:4001                         \
                          -initial-cluster "<controller_fqdn>=http://<controller_ip>:2380"  \

11. Start etcd service

   ::

       sudo service etcd start

12. Install the ``calico-compute`` package:

   ::

       sudo apt-get install calico-compute

   This step may prompt you to save your IPTables rules to make them
   persistent on restart – hit yes.

13. Configure BIRD. By default Calico assumes that you'll be deploying a
    route reflector to avoid the need for a full BGP mesh. To this end,
    it includes useful configuration scripts that will prepare a BIRD
    config file with a single peering to the route reflector. If that's
    correct for your network, you can run either or both of the following
    commands. For IPv4 connectivity between compute hosts:

    ::

        sudo calico-gen-bird-conf.sh <compute_node_ip> <route_reflector_ip> <bgp_as_number>

    And/or for IPv6 connectivity between compute hosts:

    ::

        sudo calico-gen-bird6-conf.sh <compute_node_ipv4> <compute_node_ipv6> <route_reflector_ipv6> <bgp_as_number>

    Note that you'll also need to configure your route reflector to allow
    connections from the compute node as a route reflector client. This
    configuration is outside the scope of this install document.

    If you *are* configuring a full BGP mesh you'll need to handle the BGP
    configuration appropriately. You should consult the relevant
    documentation for your chosen BGP stack.

14. Create the ``/etc/calico/felix.cfg`` file by taking a copy of the
    supplied sample config at ``/etc/calico/felix.cfg.example``.

15. Restart the Felix service with ``service calico-felix restart``.

Next Steps
----------

Now you've installed Calico, :doc:`next-steps` details how to configure
networks and use your new deployment.
