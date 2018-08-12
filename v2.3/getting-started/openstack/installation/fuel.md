---
title: Integration with Fuel
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/openstack/installation/fuel'
---

Calico plugins are available for Fuel 6.1 and 7.0, and work is in progress for
Fuel 9.  Fuel plugin code for Calico is at
[http://git.openstack.org/cgit/openstack/fuel-plugin-calico](http://git.openstack.org/cgit/openstack/fuel-plugin-calico).


## Fuel 7.0

The plugin for Fuel 7.0 is currently undergoing final review and
certification; you can find the plugin code at git.openstack.org, and
its documentation in pending changes on review.openstack.org:

-   Code:
    <https://git.openstack.org/cgit/openstack/fuel-plugin-calico/log/?h=7.0>
-   User Guide: <https://review.openstack.org/#/c/281239/>
-   Test Plan and Report: <https://review.openstack.org/#/c/282362/>

## Fuel 6.1

The rest of this document describes our integration of Calico with
Mirantis Fuel 6.1. It is presented in sections covering the following
aspects of our integration work.

-   Objective: The system that we are aiming to deploy.
-   Cluster Deployment: The procedure to follow to deploy such a system.
-   Calico Demonstration: What we recommend for demonstrating Calico
    networking function.
-   Detailed Observations: Some further detailed observations about the
    elements of the deployed system.

### Objective

We will deploy an OpenStack cluster with a controller node and *n*
compute nodes, with Calico providing the network connectivity between
VMs that are launched on the compute nodes.

The key components on the controller node will be:

-   the standard OpenStack components for a controller, including the
    Neutron service
-   the Calico/OpenStack Plugin, as a Neutron/ML2 mechanism driver
-   a BIRD instance, acting as BGP route reflector for the
    compute nodes.

The key components on each compute node will be:

-   the standard OpenStack components for a compute node
-   the Calico Felix agent
-   a BIRD instance, running BGP for that compute node.

IP connectivity between VMs that are launched within the cluster will be
established by the Calico components, according to the security groups
and rules that are configured for those VMs through OpenStack.

Cluster Deployment
------------------

The procedure for deploying such a cluster consists of the following
steps.

-   Prepare a Fuel master (aka admin) node in the usual way.
-   Install the Calico plugin for Fuel on the master node.
-   Deploy an OpenStack cluster in the usual way, using the Fuel web UI.

The following subsections flesh out these steps.

### Prepare a Fuel master node

Follow Mirantis's instructions for preparing a Fuel master node, from
the [Fuel 6.1 User Guide](https://docs.mirantis.com/openstack/fuel/fuel-6.1/user-guide.html#download-and-install-fuel).
You will need to download a Fuel 6.1 ISO image from the [Mirantis
website](https://www.mirantis.com/products/mirantis-openstack-software/).

### Install the Calico plugin for Fuel on the master node

The Calico plugin has been certified by Mirantis and is available for
download from the [Fuel Plugin Catalog](https://www.mirantis.com/products/openstack-drivers-and-plugins/fuel-plugins/).
Alternatively, you can build a copy of the plugin yourself, following
the instructions on the plugin's
[GitHub](https://github.com/openstack/fuel-plugin-calico) page.

However you obtain a copy of the Calico plugin, you will need to copy it
onto the master node and install it with:

    fuel plugins --install calico-fuel-plugin-<version>.noarch.rpm

You can check that the plugin was successfully installed using:

    fuel plugins --list

Deploy an OpenStack cluster
---------------------------

Use the Fuel web UI to deploy an OpenStack cluster in the [usual way](https://docs.mirantis.com/openstack/fuel/fuel-6.1/user-guide.html#create-a-new-openstack-environment),
with the following guidelines.

-   Create a new OpenStack environment, selecting:
    -   Juno on Ubuntu Trusty (14.x)
    -   "Neutron with VLAN segmentation" as the networking setup
-   Under the settings tab, make sure the following options are checked:
    -   "Assign public network to all nodes"
    -   "Use Calico Virtual Networking"
-   Network settings as advised in the following subsections.
-   Add nodes (for meaningful testing, you will need at least two
    compute nodes in addition to the controller).
-   Deploy changes.

### Public

Fuel assigns a 'public' IP address, from the range that you specify
here, to each node that it deploys. It also creates an OpenStack network
with this subnet, and uses that for allocating floating IPs.

Therefore these IP addresses exist to allow access from within the
cluster to the outside world, and vice versa, and should probably be
routable from the wider network where the cluster is deployed.

For the purposes of this document we'll use the 172.18.203.0/24 range of
public addresses: feel free to change this to match your own local
network.

-   IP Range: 172.18.203.40 - 172.18.203.49
-   CIDR: 172.18.203.0/24
-   Use VLAN tagging: No
-   Gateway: 172.18.203.1
-   Floating IP ranges: 172.18.203.50 - 172.18.203.59

By default, Fuel associates the public IP address with the second NIC
(i.e. `eth1`) on each node.

### Management

Fuel assigns a 'management' IP address, from the range that you specify
here, to each node that it deploys. These are the addresses that the
nodes *within* the cluster use to communicate with each other. For
example, nova-compute on each compute node communicates with the Neutron
server on the controller node by using the controller node's management
address.

-   CIDR: 192.168.0.0/24
-   Use VLAN tagging: Yes, 101

By default, Fuel associates the management IP address with the first NIC
(i.e. `eth0`) on each node.

With Calico networking, in addition:

-   BGP sessions are established, between BIRD instances on the compute
    nodes and on the route reflector, using these management IP
    addresses
-   Data between VMs on different compute nodes is routed using these
    management IP addresses, which means that it flows via the compute
    nodes' `eth0` interfaces.

### Storage

Storage networking is not needed for a simple OpenStack cluster. We left
the following settings as shown, and addresses from the specified range
are assigned, but are not used in practice.

-   CIDR: 192.168.1.0/24
-   Use VLAN tagging: Yes, 102

### Neutron L2 Configuration

Neutron L2 Configuration is not needed in a Calico system, but we have
left the following settings as shown, as we have not yet had time to
simplify the web UI for Calico networking.

-   VLAN ID range: 1000 - 1030
-   Base MAC address: fa:16:3e:00:00:00

### Neutron L3 Configuration

Neutron L3 Configuration is not needed in a Calico system, but we have
left the following settings as shown, as we have not yet had time to
simplify the web UI for Calico networking.

-   Internal network CIDR: 192.168.111.0/24
-   Internal network gateway: 192.168.111.1
-   DNS servers: 8.8.4.4, 8.8.8.8

Check BGP connectivity on the controller
----------------------------------------

Once the deployment is complete, you may wish to verify that the route
reflector running on the controller node has established BGP sessions to
all of the compute nodes.

To do this, log onto the controller node and run:

    birdc
    show protocols all

Calico Demonstration
--------------------

To demonstrate Calico networking, please run through the following
steps.

In the OpenStack web UI, under Project, Network, Networks, create a
network and subnet from which instance IP addresses will be allocated.
We use the following values.

-   Name: 'demo'
-   IP subnet: 10.65.0.0/24
-   Gateway: 10.65.0.1
-   DHCP-enabled: Yes.

Under Project, Compute, Access & Security, create two new security
groups. For each security group, select 'Manage Rules' and add two new
rules:

-   Allow incoming ICMP (ping) traffic only if it originates from other
    instances in this security group:
    -   Rule: ALL ICMP
    -   Direction: Ingress
    -   Remote: Security Group
    -   Security Group: Current Group
    -   Ether Type: IPv4
-   Enable SSH onto instances in this security group:
    -   Rule: SSH
    -   Remote: CIDR
    -   CIDR: 0.0.0.0/0

Under Project, Instances, launch a batch of VMs -- enough of them to
ensure that there will be at least one VM on each compute node -- with
the following details.

-   Flavor: m1.tiny
-   Boot from image: TestVM
-   Under the Access & Security tab, select one of your new security
    groups (split your instances roughly 50:50 between the two
    security groups).
-   Under the Networking tab, drag 'demo' into the 'Selected
    Networks' box.

Under Admin, Instances, verify that:

-   the requested number of VMs (aka instances) has been launched
-   they are distributed roughly evenly across the available compute
    hosts
-   they have each been assigned an IP address from the range that you
    configured above (e.g. 10.65.0/24)
-   they reach Active status within about a minute.

Log on to one of the VMs, e.g. by clicking on one of the instances and
then on its Console tab, and use 'ping' to verify connectivity is as
expected from the security group configuration, i.e. that you can ping
the IP addresses of all of the other VMs in the same security group, but
you cannot ping the VMs in the other security group.

Note that whilst the VMs should be able to reach other (security group
configuration permitting), they are not expected to have external
connectivity unless appropriate routing has been set up:

-   For outbound access, you need to ensure that your VMs can send
    traffic to your border gateway router (typically this will be the
    case, because usually your compute hosts will be able to do so). The
    border gateway can then perform SNAT.
-   For inbound connections, you need assign a publically routable IP
    address to your VM - that is, attach it to a network with a public
    IP address. You will also need to make sure that your border router
    (and any intermediate routers between the border router and the
    compute host) can route to that address too. The simplest way to do
    that is to peer the border router with the route reflector on
    the controller.

Detailed Observations
---------------------

This section records some more detailed notes about the state of the
cluster that results from following the above procedure.

Reading this section should not be required in order to demonstrate or
understand OpenStack and Calico function, but it may be useful as a
reference if a newly deployed system does not appear to be behaving
correctly.

### Elements required for Calico function

This subsection records elements that *are* required for Calico
function, and that we have observed to be configured and operating
correctly in the cluster.

On the controller:

-   The BIRD BGP route reflector has established sessions to all the
    compute nodes.
-   The Neutron service is running and has initialized the Calico ML2
    mechanism driver.

On each compute node:

-   The Calico Felix agent is correctly configured, and running.
-   There is an established BGP session to the route reflector on
    the controller.

### Elements not required for Calico function, but benign

This subsection records elements that are *not* required for Calico
function, but that we have observed to be operating in the cluster.
These all result from the fact that the procedure first deploys a
traditional Neutron/ML2/OVS cluster, and then modifies that to use
Calico instead of OVS, but does not clean up all of the OVS-related
elements.

We believe that all of these elements are benign, in that they don't
obstruct or fundamentally change the Calico networking behavior. However
it would be better to remove them so as to clarify the overall picture,
and maybe to improve networking performance. We plan to continue working
on this.

On the controller:

-   Various Neutron agents are running that Calico does not require.
    -   neutron-metadata-agent
    -   neutron-dhcp-agent
    -   neutron-openvswitch-agent
    -   neutron-l3-agent

On each compute node:

-   Two Neutron agents are running that Calico does not require.
    -   neutron-metadata-agent
    -   neutron-openvswitch-agent
-   There is a complex set of OVS bridges present, that Calico does
    not require.
