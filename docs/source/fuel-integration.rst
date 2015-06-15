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

Integration with Mirantis Fuel 5.1
==================================

This document describes our experimental integration of Calico with the
Mirantis Fuel system for rapidly deploying an OpenStack cluster.

It is presented in sections covering the following aspects of our integration
work.

- Objective: The system that we are aiming to deploy.
- Cluster Deployment: The procedure to follow to deploy such a system.
- Calico Demonstration: What we recommend for demonstrating Calico
  networking function.
- Detailed Observations: Some further detailed observations about the
  elements of the deployed system.

Objective
---------

We will deploy an OpenStack cluster with a controller node and *n*
compute nodes, with Calico providing the network connectivity between
VMs that are launched on the compute nodes.

The key components on the controller node will be:

- the standard OpenStack components for a controller, including the
  Neutron service
- the Calico/OpenStack Plugin, as a Neutron/ML2 mechanism driver
- a BIRD instance, acting as BGP route reflector for the compute
  nodes.

The key components on each compute node will be:

- the standard OpenStack components for a compute node
- the Calico Felix agent
- a BIRD instance, running BGP for that compute node.

IP connectivity between VMs that are launched within the cluster will
be established by the Calico components, according to the security
groups and rules that are configured for those VMs through OpenStack.

Cluster Deployment
------------------

The procedure for deploying such a cluster consists of the following
steps.

- Prepare a Fuel master (aka admin) node in the usual way.
- Apply some changes to the Puppet files on the master node.
- Deploy an OpenStack cluster in the usual way, using the Fuel web UI.
- Run a route reflector configuration script on the controller node.

The following subsections flesh out these steps.

Prepare a Fuel master node
~~~~~~~~~~~~~~~~~~~~~~~~~~

Follow Mirantis's instructions for preparing a Fuel master node,
starting from `here`_. Typically this involves
downloading an ISO image and then booting a fresh machine from that
ISO.

Our Calico-related changes (described next) take the Fuel 5.1 release
as their base, so it would be most reliable to download and use the
ISO image for 5.1.

.. _here: https://software.mirantis.com/

Apply changes to Puppet files on the master node
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

We are developing Calico-related Puppet file changes in a
`fork of Mirantis's fuel-library repository`_. Our changes are in the
``calico2`` branch.

Clone this repository and checkout the ``calico2`` branch.  This can be
done on any machine where you have Git and that is convenient for you
to develop on, and from which you can access the Fuel master node.
Linux-based machines will probably be more straightforward than Windows-based
ones, because it avoids the pitfalls of line ending and permissions
conversion when synchronizing files from this machine onto the Fuel
master node.

First, obtain the code::

    git clone https://github.com/Metaswitch/fuel-library.git
    cd fuel-library
    git checkout calico2

Copy the puppet files from this repository to an interim location on
the Fuel master node.

::

    sshpass -pr00tme rsync -rv --delete deployment root@MASTER-NODE-IP:fuel-library/

On the master node, go to that interim location, then run the
following commands to modify the relevant files under ``/etc/puppet``::

    cd deployment
    bash install.sh

The output from the last command should look something like this::

    [root@mirantis-fuelmaster2 deployment]# sh install.sh
    sending incremental file list
    calico/files/
    calico/files/calico_compute.sh
    calico/files/calico_controller.sh
    calico/files/calico_route_reflector.sh
    calico/files/extra.list
    calico/files/extra_prefs
    calico/files/network-settings.org
    calico/files/todo.org
    calico/manifests/
    calico/manifests/init.pp
    calico/manifests/params.pp
    calico/manifests/stop_neutron_agents.pp

    sent 12827 bytes  received 211 bytes  26076.00 bytes/sec
    total size is 12105  speedup is 0.93
    Overwrite osnailyfacter/manifests/cluster_simple.pp
    Overwrite osnailyfacter/examples/site.pp

.. _fork of Mirantis's fuel-library repository: https://github.com/Metaswitch/fuel-library

Deploy an OpenStack cluster
---------------------------

Use the Fuel web UI to deploy an OpenStack cluster in the usual way,
with the following guidelines.

- Select non-HA controller (i.e. "Multi-node" option).
- Select neutron with VLAN segmentation, for networking.
- Select Ubuntu Precise as the OS.
- Check the "Assign public network to all nodes" option (under the Settings
  tab).
- You'll need at least two compute nodes, for a meaningful test of
  Calico networking.
- Network settings as advised in the following subsections.

Public
~~~~~~

Fuel assigns a 'public' IP address, from the range that you specify
here, to each node that it deploys.  It also creates an OpenStack
network with this subnet, and uses that for allocating floating IPs.

Therefore these IP addresses exist to allow access from within the
cluster to the outside world, and vice versa, and should probably be
routable from the wider network where the cluster is deployed.

For the purposes of this document we'll use the 172.18.203.0/24 range of
public addresses: feel free to change this to match your own local network.

- IP Range: 172.18.203.40 - 172.18.203.49
- CIDR: 172.18.203.0/24
- Use VLAN tagging: No
- Gateway: 172.18.203.1

By default, Fuel associates the public IP address with the second NIC
(i.e. ``eth1``) on each node.

Management
~~~~~~~~~~

Fuel assigns a 'management' IP address, from the range that you
specify here, to each node that it deploys.  These are the addresses
that the nodes *within* the cluster use to communicate with each
other.  For example, nova-compute on each compute node communicates
with the Neutron server on the controller node by using the controller
node's management address.

- CIDR: 192.168.0.0/24
- Use VLAN tagging: Yes, 101

By default, Fuel associates the management IP address with the first
NIC (i.e. ``eth0``) on each node.

With Calico networking, in addition:

- BGP sessions are established, between BIRD instances on the compute
  nodes and on the route reflector, using these management IP
  addresses
- Data between VMs on different compute nodes is routed using these
  management IP addresses, which means that it flows via the compute
  nodes' ``eth0`` interfaces.

Storage
~~~~~~~

Storage networking is not needed for a simple OpenStack cluster.  We
left the following settings as shown, and addresses from the specified
range are assigned, but are not used in practice.

- CIDR: 192.168.1.0/24
- Use VLAN tagging: Yes, 102

Neutron L2 Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Neutron L2 Configuration is not needed in a Calico system, but we have
left the following settings as shown, as we have not yet had time to
simplify the web UI for Calico networking.

- VLAN ID range: 1000 - 1030
- Base MAC address: fa:16:3e:00:00:00

Neutron L3 Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

Neutron L3 Configuration is not needed in a Calico system, but we have
left the following settings as shown, as we have not yet had time to
simplify the web UI for Calico networking.

- Internal network CIDR: 192.168.111.0/24
- Internal network gateway: 192.168.111.1
- Floating IP ranges: 172.18.203.50 - 172.18.203.59
- DNS servers: 8.8.4.4, 8.8.8.8

Configure BGP route reflector on the controller
-----------------------------------------------

Once the deployment is complete -- and also, if you later add more
compute nodes to the deployment -- you need to update the BGP route
reflector configuration on the controller node.

To do this, log onto the controller node and run::

    /calico_route_reflector.sh

To verify that BGP sessions are established to all the compute nodes,
you can then do::

    birdc
    show protocols all

Calico Demonstration
--------------------

To demonstrate Calico networking, please run through the following
steps.

In the OpenStack web UI, under Project, Network, Networks, create a
network and subnet from which instance IP addresses will be allocated.
We use the following values.

- Name: 'demo'
- IP subnet: 10.65.0/24
- Gateway: 10.65.0.1
- DHCP-enabled: Yes.

Also in the OpenStack web UI, under Admin, System Info, Network
Agents, verify that there is an instance of 'Felix (Calico agent)'
running on each compute node, and that its Status is Up.

Under Project, Instances, launch a batch of VMs -- enough of them to
ensure that there will be at least one VM on each compute node -- with
the following details.

- Flavor: m1.tiny
- Boot from image: TestVM
- Under the Networking tab, drag 'demo' into the 'Selected Networks'
  box.

Under Admin, Instances, verify that:

- the requested number of VMs (aka instances) has been launched
- they are distributed roughly evenly across the available compute
  hosts
- they have each been assigned an IP address from the range that you
  configured above (e.g. 10.65.0/24)
- they reach Active status within about a minute.

Log on to one of the VMs, e.g. by clicking on one of the instances and
then on its Console tab, and use 'ping' to verify connectivity to the
IP address of each other VM.

Under Project, Access & Security, change the rules of the 'default'
security group so that they don't allow access between all VMs in that
group, but instead only to and from particular VM IP addresses.

Log on to one of the VMs that you would now expect *not* to have
access to all of the others, and verify that it can still ping the VMs
that you would expect, and cannot ping the others.

Detailed Observations
---------------------

This section records some more detailed notes about the state of the
cluster that results from following the above procedure with HEAD
commit 854d2353 from `our fork of the Fuel library
<https://github.com/Metaswitch/fuel-library>`__.
Reading this section should not be required in order to demonstrate or
understand OpenStack and Calico function, but it may be useful as a reference
if a newly deployed system does not appear to be behaving correctly.

Elements required for Calico function
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This subsection records elements that *are* required for Calico
function, and that we have observed to be configured and operating
correctly in the cluster.

On the controller:

- The BIRD BGP route reflector has established sessions to all the
  compute nodes.
- The Neutron service is running and has initialized the Calico ML2
  mechanism driver.

On each compute node:

- The Calico Felix agent is correctly configured, and running.
- There is an established BGP session to the route reflector on the
  controller.

Elements not required for Calico function, but benign
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This subsection records elements that are *not* required for Calico
function, but that we have observed to be operating in the cluster.
These all result from the fact that the procedure first deploys a
traditional Neutron/ML2/OVS cluster, and then modifies that to use
Calico instead of OVS, but does not clean up all of the OVS-related
elements.

We believe that all of these elements are benign, in that they don't
obstruct or fundamentally change the Calico networking behavior.
However it would be better to remove them so as to clarify the overall
picture, and maybe to improve networking performance.  We plan to
continue working on this.

On the controller:

- Various Neutron agents are running that Calico does not require.

  - neutron-ns-metadata-proxy
  - neutron-metadata-agent
  - neutron-dhcp-agent
  - neutron-openvswitch-agent
  - neutron-l3-agent

On each compute node:

- Two Neutron agents are running that Calico does not require.

  - neutron-metadata-agent
  - neutron-openvswitch-agent

- There is a complex set of OVS bridges present, that Calico does not
  require.

In the OpenStack configuration:

- There is a router configured, that Calico doesn't require.
- There are networks configured with subnets 192.168.111.0/24 and
  172.18.203.0/24, which Calico doesn't require.
