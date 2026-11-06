# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import collections
import functools
import logging
import random
import threading

from calicotest.common import osutils
from calicotest.common.node import Node
from calicotest.common.stringutils import id_gen
from calicotest.common.testutils import retry_until_success, ThreadWithReturn
from calicotest.openstack.basetest import TestBase
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.controller import Controller
from calicotest.openstack.vm import WrongState
from calicotest.settings import (
    CIRROS,
    DEFAULT_NET_NAME,
    FLOAT_IPV4,
    IPV4_ONLY,
    IPV6_WITH_APPS,
)

_log = logging.getLogger(__name__)


class Topology(TestBase):
    """
    Superclass for all test topologies.  We expect that a test topology
    will have multiple tests within it which will all use the same setup.
    """

    controller = None
    regions = []
    controllers_by_region = collections.OrderedDict()
    my_ipv4 = None
    my_ipv6 = None

    @classmethod
    def setUpClass(cls):
        """
        Setup the class data common to this test suite.
        """
        super(Topology, cls).setUpClass()

        # Use the test_node_ip from the cluster layout file if there is one.  If
        # not, try and figure out what our IP address is...
        if LAYOUT.test_node_ip is None:
            cls.my_ipv4 = osutils.get_local_ip(4)
            cls.my_ipv6 = osutils.get_local_ip(6)
        else:
            cls.my_ipv4 = LAYOUT.test_node_ip
            if cls.my_ipv4.startswith("192.168"):
                last_two = cls.my_ipv4.split(".")[-2:]
                cls.my_ipv6 = "fd00:%s::%s" % tuple(last_two)
        cls.regions = []
        cls.controllers_by_region = collections.OrderedDict()
        for r, n in sorted(LAYOUT.control_node_by_region.items()):
            assert len(cls.regions) == 0 or cls.regions[-1] != r, "Duplicate region?"
            cls.regions.append(r)
            controller = Controller(
                n.fqdn, n.username, n.password, n.admin_password, cls.my_ipv4, region=r
            )
            cls.controllers_by_region[r] = controller
            if n == LAYOUT.control_node:
                # For tests that aren't region-aware, store off the single
                # control node that they should use.
                cls.controller = controller

            # Get admin to tidy up the system.
            controller.tenants["admin"].cleanup_system()

    @classmethod
    def tearDownClass(cls):
        """
        Common teardown processing.
        """
        super(Topology, cls).tearDownClass()

    @classmethod
    def create_vm(
        cls,
        tenant="admin",
        image=CIRROS,
        flavor=None,
        networks=None,
        security_groups="default",
        availability_zone=None,
        ubuntu_speedup_sudo=False,
        region=None,
    ):
        """
        Creates a VM, using sensible, overrideable defaults.

        :param tenant: The Tenant that should own this VM.
        :param networks: The names of the networks that this VM should be on.
        :param security_groups: The security groups that should be assigned to
                               this VM.  This can be a single group or a list.
        :param availability_zone: The availability zone (or the compute node)
        :param image: the name of the image that the VM should use
        :param flavor: the flavor that the VM should use
        :param ubuntu_speedup_sudo: if true bootup will take longer, but using
                                    sudo on the vm will be much faster - only
                                    needed on Ubuntu vms.
        :param region: OpenStack region (defaults to the first region in the
                       config)
        :returns: whatever controller.create_vm passes back (currently a
                  VM object).
        """
        if networks is None:
            networks = [DEFAULT_NET_NAME]
        if not flavor:
            flavor = image.flavor

        controller = cls.controllers_by_region.get(region, cls.controller)
        vm = controller.create_vm(
            id_gen(),
            tenant=tenant,
            image=image,
            flavor=flavor,
            security_groups=security_groups,
            networks=networks,
            availability_zone=cls.zonify(availability_zone),
            ubuntu_speedup_sudo=ubuntu_speedup_sudo,
        )
        assert vm is not None, "Failed to create VM with parameters %s" % locals()
        return vm

    @classmethod
    def create_vm_parallel(
        cls,
        tenant="admin",
        image=CIRROS,
        flavor=None,
        networks=[DEFAULT_NET_NAME],
        security_groups="default",
        availability_zone=None,
        ubuntu_speedup_sudo=False,
        region=None,
    ):
        """
        Starts a thread which creates a VM and returns the VM upon completion.

        :param tenant: The Tenant that should own this VM.
        :param networks: The name of the networks that this VM should be on.
        :param security_groups: The security groups that should be assigned to
                               this VM.  This can be a single group or a list.
        :param availability_zone: The availability zone (or the compute node)
        :param image: the name of the image that the VM should use
        :param flavor: the flavor that the VM should use
        :param ubuntu_speedup_sudo: if true bootup will take longer, but using
                                    sudo on the vm will be much faster - only
                                    needed on Ubuntu vms.
        :param region: OpenStack region (defaults to the first region in the
                       config)
        :returns: a ThreadWithReturn which is running cls.create_vm
        """
        vm_kwargs = {
            "tenant": tenant,
            "image": image,
            "flavor": flavor,
            "networks": networks,
            "security_groups": security_groups,
            "availability_zone": availability_zone,
            "ubuntu_speedup_sudo": ubuntu_speedup_sudo,
            "region": region,
        }
        vm_thread = ThreadWithReturn(target=cls.create_vm, kwargs=vm_kwargs)
        vm_thread.start()
        return vm_thread

    @classmethod
    def delete_vm(cls, name, tenant="admin", region=None):
        """
        Deletes a VM.

        :param name: string specifying the name of the VM to delete.
        :param tenant: string specifying the name of the tenant who should
                       perform this action.
        :param region: OpenStack region (defaults to the first region in the
                       config)
        """
        _log.info("Deleting VM: name=%s tenant=%s", name, tenant)
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.delete_vm(name, tenant=tenant)

    @classmethod
    def create_security_group(cls, name, description="", region=None):
        """
        Creates a security group.

        :param name: string specifying the name of the security group.
        :param description: string with the description of the security group.
        :param region: OpenStack region (defaults to the first region in the
                       config)

        :returns: whatever controller.create_security_group passes back.
                  Currently a string with the name of the security group.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        return controller.create_security_group(name, description)

    @classmethod
    def add_sec_group_to_vm(cls, vm_name, group_name, tenant="admin", region=None):
        """
        Adds a security group to a VM.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.tenants[tenant].vms[vm_name].add_security_group(group_name)

    @classmethod
    def remove_sec_group_from_vm(cls, vm_name, group_name, tenant="admin", region=None):
        """
        Removes a security group from a VM.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.tenants[tenant].vms[vm_name].remove_security_group(group_name)

    @classmethod
    def add_ssh_rule(cls, groupname, region=None):
        """
        Adds a rule allowing ssh from the test machine to a security group.

        :param groupname: the name of the security group to add the rule to
        """
        cls.add_rule(groupname, "tcp", 22, 22, cls.my_ipv4 + "/32", region=region)

        # Only add a rule for SSH'ing over IPv6 if the host has an IPv6 address
        if cls.my_ipv6 is not None:
            cls.add_rule(
                groupname,
                "tcp",
                22,
                22,
                cls.my_ipv6 + "/128",
                ethertype="IPv6",
                region=region,
            )

    @classmethod
    def add_rule(
        cls,
        groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidr=None,
        update_cache=True,
        ethertype="IPv4",
        region=None,
    ):
        """
        Adds a rule to a security group.

        :param groupname: the name of the security group to add the rule to
        :param proto: the protocol to put in the rule.
                      One of: 'tcp', 'udp', 'icmp', or the protocol number
        :param from_port: The from port number, for TCP or UDP. For ICMP this
                          is the message type
        :param to_port: The to port number
        :param cidr: the IP address range (CIDR format) to allow connections
                     to/from.
        :param update_cache: Whether we need to update our cache to resync
        the group data after updates.  Set to False if making a large number
        of updates to a group, and set to True on the last update.
        :param ethertype: The type of IP.
                          One of 'IPv4' and 'IPv6'
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.add_security_group_rule(
            groupname,
            proto=proto,
            from_port=from_port,
            to_port=to_port,
            cidr=cidr,
            update_cache=update_cache,
            ethertype=ethertype,
        )

    @classmethod
    def add_cidr_rules(
        cls,
        groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidrs=None,
        update_cache=True,
        ethertype="IPv4",
        region=None,
    ):
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.add_security_group_rules(
            groupname,
            proto=proto,
            from_port=from_port,
            to_port=to_port,
            cidrs=cidrs,
            update_cache=update_cache,
            ethertype=ethertype,
        )

    @classmethod
    def delete_rule(
        cls,
        groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidr=None,
        update_cache=True,
        region=None,
    ):
        """
        Deletes a rule to a security group.

        :param groupname: the name of the security group to add the rule to
        :param proto: the protocol to put in the rule.
                      One of: 'tcp', 'udp', 'icmp' or a protocol number
        :param from_port: The from port number for tcp or udp, or the message
                          type for icmp
        :param to_port: The to port number
        :param cidr: the IP address range (CIDR format) to allow connections
                     to/from.
        :param update_cache: Whether we need to update our cache to resync
        the group data after updates.  Set to False if making a large number
        of updates to a group, and set to True on the last update.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.delete_security_group_rule(
            groupname,
            proto=proto,
            from_port=from_port,
            to_port=to_port,
            cidr=cidr,
            update_cache=update_cache,
        )

    @classmethod
    def add_group_rule(cls, groupname, permitted_groupname, proto, region=None):
        """
        Adds a group rule to a security group.

        :param groupname: the name of the security group to add the rule to.
        :param proto: the protocol to put in the rule.
                      One of: 'tcp', 'udp', 'icmp'
        :param permitted_groupname: the name of the group we giving access to
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.add_security_group_rule(
            groupname, proto=proto, permitted_groupname=permitted_groupname
        )

    @classmethod
    def delete_group_rule(cls, groupname, permitted_groupname, proto, region=None):
        """
        Deletes a group rule to a security group.

        :param groupname: the name of the security group to add the rule to.
        :param proto: the protocol to put in the rule.
                      One of: 'tcp', 'udp', 'icmp'
        :param permitted_groupname: the name of the group we giving access to
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.delete_security_group_rule(
            groupname, proto=proto, permitted_groupname=permitted_groupname
        )

    @classmethod
    def add_group_ping_rule(cls, groupname, permitted_groupname=None, region=None):
        """
        Adds a rule to a security group to allow machines within a security
        group to ping each other.

        :param groupname: the name of the security group to add the rule to.
        :param permitted_groupname: the name of the remote security group.
        """
        if permitted_groupname is None:
            permitted_groupname = groupname
        cls.add_group_rule(groupname, permitted_groupname, "icmp", region=region)

    @classmethod
    def delete_group_ping_rule(cls, groupname, permitted_groupname=None, region=None):
        """
        Deletes a rule to a security group to allow machines within a security
        group to ping each other.

        :param groupname: the name of the security group to delete the rule
        from.
        :param permitted_groupname: the name of the remote security group.
        """
        if permitted_groupname is None:
            permitted_groupname = groupname
        cls.delete_group_rule(groupname, permitted_groupname, "icmp", region=region)

    @classmethod
    def delete_group_default_egress_rules(cls, groupname, region=None):
        """
        Delete the default egress rules in this security group
        :param groupname: the name of the security group to delete the rules
        from.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.delete_security_group_rule(
            groupname, direction="egress", ethertype="IPv4"
        )
        controller.delete_security_group_rule(
            groupname, direction="egress", ethertype="IPv6"
        )

    @classmethod
    def add_group_default_egress_rules(cls, groupname, region=None):
        """
        Add the default egress rules to this security group
        :param groupname: the name of the security group to add the rules to
        :return:
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.add_security_group_rule(
            groupname, direction="egress", ethertype="IPv4"
        )
        controller.add_security_group_rule(
            groupname, direction="egress", ethertype="IPv6"
        )

    @classmethod
    def add_egress_group_ping_rule(
        cls, groupname, permitted_groupname=None, region=None
    ):
        """
        Adds an egress rule to a security group to allow machines within a
        security group to send messages out to another group
        :param groupname: the name of the security group to add the rule to
        :param permitted_groupname: the name of the remote security group
        """
        if permitted_groupname is None:
            permitted_groupname = groupname
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.add_security_group_rule(
            groupname,
            permitted_groupname=permitted_groupname,
            direction="egress",
            proto="icmp",
        )

    @classmethod
    def delete_egress_group_ping_rule(
        cls, groupname, permitted_groupname=None, region=None
    ):
        """
        Adds an egress rule to a security group to allow machines within a
        security group to send messages out to another group
        :param groupname: the name of the security group to add the rule to
        :param permitted_groupname: the name of the remote security group
        """
        if permitted_groupname is None:
            permitted_groupname = groupname
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.delete_security_group_rule(
            groupname,
            permitted_groupname=permitted_groupname,
            direction="egress",
            proto="icmp",
        )

    @classmethod
    def create_network(
        cls, name, cidr=None, cidr_v6=None, router_external=False, region=None
    ):
        """
        Adds a network.

        :param name: the name of the new network.
        :param cidr: required if the new network is IPv4. This is the ip
                     address range for the new network in cidr format
        :param cidr_v6: required if the new network is IPv6. This is the ip
                        address range for the new network in cidr format
        :returns: the name of the new network.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        return controller.create_network(
            name, cidr=cidr, cidr_v6=cidr_v6, router_external=router_external
        )

    @classmethod
    def delete_network(cls, net_name, region=None):
        """
        Deletes a network.

        :param net_name: string specifying the name of the network to delete.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        return controller.delete_network(net_name)

    @classmethod
    def create_tenant(cls, name, region=None, project_parent_id=None):
        """
        Adds a tenant.

        :param name: string specifying the name of the tenant to create.

        :returns: the name of the new tenant.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        tenant = controller.create_tenant(name, project_parent_id=project_parent_id)
        return tenant.name

    @classmethod
    def delete_tenant(cls, name, region=None):
        """
        Deletes a tenant.

        :param name: string specifying the name of the tenant to delete.
        """
        controller = cls.controllers_by_region.get(region, cls.controller)
        controller.delete_tenant(name)

    @classmethod
    def zonify(cls, zone_or_node):
        """
        Return the name of the availability zone from the supplied zone or
        node.

        If a node is supplied, then the zone is basically the first section of the
        FQDN (the tests create an availability zone for each compute host, named
        after the host).  Otherwise the zone is left unchanged.

        :param zone_or_node: The availability zone or the node.
        :return: The availability zone.
        """
        if isinstance(zone_or_node, Node):
            return zone_or_node.fqdn.split(".")[0]
        else:
            return zone_or_node

    @classmethod
    def create_security_group_with_basic_rules(cls, name, region=None):
        """
        Creates and returns a security group with the standard rules - so that
        you can ssh into boxes in the group, and they can ping each other.
        :param name: The name to give the security group
        :return: The security group created
        """
        _log.info("Creating security group: %s" % name)
        security_group = cls.create_security_group(name, region=region)
        cls.add_ssh_rule(name, region=region)
        cls.add_group_ping_rule(name, region=region)
        return security_group

    def check_port_status(self, ip, expected_state, region=None):
        """
        Raises WrongState exception if the state of the neutron port
        with a particular IP isn't as expected.
        :param ip: string containing the IP of interest
        :param expected_state: string containing the state we expect
                               for the port
        """
        myport = self.get_port(ip, region=region)
        _log.debug(
            "Found port with ip %s in state %s, id=%s, device_id=%s",
            ip,
            myport["status"],
            myport["id"],
            myport["device_id"],
        )

        if myport["status"] != expected_state:
            raise WrongState(
                "Port with IP: %s in wrong state: %s - expected %s"
                % (ip, myport["status"], expected_state)
            )

    def get_port(self, ip, region=None):
        """
        Finds the neutron port with a particular IP and returns it.
        """
        # An example neutron port:
        # { u'admin_state_up': True,
        #   u'allowed_address_pairs': [],
        #   u'binding:host_id': u'calico-host1',
        #   u'binding:profile': {   },
        #   u'binding:vif_details': {   u'mac_address': u'00:61:fe:ed:ca:fe',
        #                               u'port_filter': True},
        #   u'binding:vif_type': u'tap',
        #   u'binding:vnic_type': u'normal',
        #   u'device_id': u'16cfbef4-e1f6-4c2e-a912-9af5703ad95e',
        #   u'device_owner': u'compute:calico-host1',
        #   u'extra_dhcp_opts': [],
        #   u'fixed_ips':
        #       [ {  u'ip_address': u'10.28.0.11',
        #            u'subnet_id': u'9daf743d-6ef0-4fec-a1c9-75e2e1a1f5b8'},
        #         {  u'ip_address': u'fd5f:5d21:845:1c2e:2::b',
        #            u'subnet_id': u'19e11636-5c15-4b19-94c1-744983b8f83e'}],
        #   u'id': u'7e973ae2-62d7-46a1-8b5d-732af73c1333',
        #   u'mac_address': u'fa:16:3e:d2:e9:67',
        #   u'name': u'',
        #   u'network_id': u'67317947-8a15-4af0-bad7-f5ca9c5656ce',
        #   u'security_groups': [   u'80d6840a-53f8-4a69-b593-339ee53cb46f'],
        #   u'status': u'ACTIVE',
        #   u'tenant_id': u'3a10452de9304f0aa50af009bcb2a07e'},

        controller = self.controllers_by_region.get(region, self.controller)
        neutron = controller.tenants["admin"].neutron
        # Find the port with the IP of interest
        myport = None
        for port in neutron.list_ports()["ports"]:
            for addr in port["fixed_ips"]:
                if addr["ip_address"] == ip:
                    myport = port
                    break
            if myport:
                break
        # Check we actually found it
        assert myport is not None, "Couldn't find a port with IP %s" % ip
        return myport

    def check_service_status(self, hostname, service_name, expect_alive, region=None):
        """
        Raises ServiceStateError exception if service['alive'] isn't as
        expected.
        :param hostname: name of host to check
        :param service_name: name of service to check
        :param expect_alive: True if service is expected to be up
        """
        service = None
        for serv in self.get_agent_list(region=region):
            if serv["host"] == hostname and serv["binary"] == service_name:
                service = serv
        assert service is not None, ("Unable to find %s on %s" % service_name, hostname)

        _log.debug(
            "service %s on %s alive = %s",
            service["binary"],
            service["host"],
            service["alive"],
        )

        if service["alive"] != expect_alive:
            raise ServiceStateError(
                "service['alive'] is {0:s} for {1:s} on {2:s} - expected {3:s}".format(
                    str(service["alive"]), service_name, hostname, str(expect_alive)
                )
            )

    def get_agent_list(self, region=None):
        controller = self.controllers_by_region.get(region, self.controller)
        return controller.tenants["admin"].neutron.list_agents()["agents"]

    def assert_felix_agent_up(self, region=None):
        # Check neutron service list shows a felix for each compute
        # host and that they are all green and happy.
        compute_nodes = LAYOUT.compute_nodes_by_region.get(region, LAYOUT.compute_nodes)
        compute_node_names = [node.fqdn.split(".")[0] for node in compute_nodes]

        _log.info("Check calico-felix is up on all nodes")
        felix_down_nodes = []
        for service in self.get_agent_list(region=region):
            _log.debug(
                "service %s on %s alive = %s",
                service["binary"],
                service["host"],
                service["alive"],
            )
            if service["binary"] == "calico-felix":
                # test node also has calico-felix running
                if not ("test-node" in service["host"]):
                    compute_node_names.remove(service["host"])
                    if not service["alive"]:
                        felix_down_nodes.append(service["host"])

        self.assertTrue(
            len(compute_node_names) == 0,
            msg="Didn't find felix on %s.  Felix was down on %s "
            % (compute_node_names, felix_down_nodes),
        )

    @classmethod
    def on_failure(cls, test_id=None):
        try:
            for r, controller in cls.controllers_by_region.items():
                _log.info("Failure occurred, agent status for region %s...", r)
                admin = controller.tenants["admin"]
                agents = admin.neutron.list_agents()["agents"]
                for agent in agents:
                    _log.info("Agent status: %s", agent)
        finally:
            super(Topology, cls).on_failure(test_id=test_id)

    def _datamodel_region_arg(self):
        # Compute the region arg that we need to give on datamodel_v3
        # calls, when our intention is to work with resources in the
        # first controller's region.
        #
        # If there is more than one region, we're in a multi-region
        # test, and we need to provide the name of the first region.
        #
        # Otherwise we're in a single-region test, and in that case we
        # need to pass None, so as to work with resources in the
        # traditional "openstack" namespace.
        if len(self.regions) > 1:
            return self.controller.region
        return None


class TopologyBasic(Topology):
    """
    Sets up one VM per host, and then one more VM so that at least one
    connection is intra-host. All VMs are in the same tenant, network and
    security group.
    """

    @classmethod
    def setUpClass(cls):
        super(TopologyBasic, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.vms = []
        vm_threads = []
        for node in LAYOUT.compute_nodes:
            vm_threads.append(cls.create_vm_parallel(availability_zone=node))
        node = LAYOUT.compute_nodes[0]
        vm_threads.append(cls.create_vm_parallel(availability_zone=node))

        for vm_thread in vm_threads:
            cls.vms.append(vm_thread.join())

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.vms:
            cls.delete_vm(vm.name)
        super(TopologyBasic, cls).tearDownClass()


class Topology2Networks(Topology):
    """
    Sets up VMs in the same tenant and security group, across 2
    networks and all hosts.
    """

    @classmethod
    def setUpClass(cls):
        super(Topology2Networks, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.net1_vms = []
        cls.net2_vms = []
        cls.network = cls.create_network(IPV4_ONLY.name, cidr=IPV4_ONLY.cidr)
        # Setup a VM on each host in each network
        # And another pair on one of the hosts
        # So that we check both inter-host and intra-host connectivity.
        on_net1 = True  # Just to distribute the load of VMs.
        net1_vm_threads = []
        net2_vm_threads = []
        for node in LAYOUT.compute_nodes:
            if on_net1:
                net1_vm_threads.append(cls.create_vm_parallel(availability_zone=node))
            else:
                net2_vm_threads.append(
                    cls.create_vm_parallel(
                        availability_zone=node, networks=[IPV4_ONLY.name]
                    )
                )
            on_net1 = not on_net1

        node = LAYOUT.compute_nodes[0]
        vm_thread = cls.create_vm_parallel(availability_zone=node)

        # Wait for the threads to complete and store the created VMs
        for net1_vm_thread in net1_vm_threads:
            cls.net1_vms.append(net1_vm_thread.join())
        for net2_vm_thread in net2_vm_threads:
            cls.net2_vms.append(net2_vm_thread.join())
        cls.net1_vms.append(vm_thread.join())

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.net1_vms:
            cls.delete_vm(vm.name)
        for vm in cls.net2_vms:
            cls.delete_vm(vm.name)

        # Can't delete network while VMs are using it
        retry_until_success(
            functools.partial(cls.delete_network, IPV4_ONLY.name),
            context_string="Topology2Networks.tearDownClass",
        )
        super(Topology2Networks, cls).tearDownClass()


class TopologyBasicTenants(Topology):
    """
    Sets up VMs in the same security group and network, across 2
    tenants and all hosts.
    """

    @classmethod
    def setUpClass(cls):
        super(TopologyBasicTenants, cls).setUpClass()
        _log.info("Running %s.setUpClass", cls.__name__)
        cls.tenant1_vms = []
        cls.tenant2_vms = []
        cls.tenant = cls.create_tenant("tenant2")
        # Setup a VM on each host in each tenant
        # And another pair on one of the hosts
        # So that we check both inter-host and intra-host connectivity.
        _log.info("Tenant created, starting to create VMs")
        on_tenant1 = True
        tenant1_vm_threads = []
        tenant2_vm_threads = []
        for node in LAYOUT.compute_nodes:
            if on_tenant1:
                _log.info("Creating VM using tenant 'admin' on %s", node)
                tenant1_vm_threads.append(
                    cls.create_vm_parallel(availability_zone=node)
                )
            else:
                _log.info("Creating VM using tenant 'tenant2' on %s", node)
                tenant2_vm_threads.append(
                    cls.create_vm_parallel(availability_zone=node, tenant=cls.tenant)
                )
            on_tenant1 = not on_tenant1

        node = LAYOUT.compute_nodes[0]
        vm_thread = cls.create_vm_parallel(availability_zone=node)

        # Wait for the threads to complete and store the created VMs
        for tenant1_vm_thread in tenant1_vm_threads:
            cls.tenant1_vms.append(tenant1_vm_thread.join())
        for tenant2_vm_thread in tenant2_vm_threads:
            cls.tenant2_vms.append(tenant2_vm_thread.join())
        cls.tenant1_vms.append(vm_thread.join())
        _log.info("VMs created. Setup complete.")

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)
        for vm in cls.tenant1_vms:
            cls.delete_vm(vm.name)
        for vm in cls.tenant2_vms:
            cls.delete_vm(vm.name, tenant=cls.tenant)
        cls.delete_tenant(cls.tenant)
        super(TopologyBasicTenants, cls).tearDownClass()


class Topology2SecurityGroupsBase(Topology):
    """
    Abstract class. Implemented to bring together the common functionality of
    Topology2SecurityGroups and Topology2SecurityGroupsUbuntu. Look at them to
    get an idea for implementation details. We expect that the following
    attributes will have been set in the subclass:
    -default_group_image_type
    -group2_image_type
    -max_number_of_ubuntu_vms_per_group
    -add_random_vm
    In the same vein, setUpClass(...) is not defined here! Any subclass should
    create one that is compatible with the tearDownClass(...) that is defined
    here. We expect that set_up_vms(...) will be called in any such setUpClass.
    """

    @classmethod
    def set_up_vms(cls):
        """
        Sets up VMs as per the specified class attributes.
        """

        # Setup a VM on each host in each security group
        # And another pair on one of the hosts
        # So that we check both inter-host and intra-host connectivity.
        # We check if we have made more vms per group than we are allowed
        # Ubuntu vms, and if so we change the image_type to CIRROS for the
        # rest.

        cls.other_vms = []
        cls.default_group = []
        cls.group2 = []

        default_group_threads = []
        group2_threads = []
        for counter, node in enumerate(LAYOUT.compute_nodes):
            _log.info("Creating 2 VMs on %s", node)
            if counter == cls.max_number_of_ubuntu_vms_per_group:
                cls.default_group_image_type = CIRROS
                cls.group2_image_type = CIRROS
            default_group_threads.append(
                cls.create_vm_parallel(
                    availability_zone=node,
                    security_groups="default",
                    image=cls.default_group_image_type,
                )
            )
            group2_threads.append(
                cls.create_vm_parallel(
                    availability_zone=node,
                    security_groups="group2",
                    image=cls.group2_image_type,
                )
            )
        for default_group_thread in default_group_threads:
            cls.default_group.append(default_group_thread.join())
        for group2_thread in group2_threads:
            cls.group2.append(group2_thread.join())

        if cls.add_random_vm:
            node = random.choice(LAYOUT.compute_nodes[0:1])
            _log.info("Creating additional VM on %s", node)
            # Our hosts don't like more than two Ubuntu vms, so this should be
            # a Cirros VM regardless of choice
            cls.group2.append(
                cls.create_vm(
                    availability_zone=node, security_groups="group2", image=CIRROS
                )
            )
        threads = []
        for vm in cls.default_group + cls.group2 + cls.other_vms:
            # Allow sudo access on Ubuntu vms by default
            if vm.image == IPV6_WITH_APPS:
                _log.info("Allowing sudo on Ubuntu host")
                thread = threading.Thread(target=vm.speedup_sudo_on_ubuntu)
                thread.daemon = True
                threads.append(thread)
                thread.start()
        for thread in threads:
            thread.join()

    @classmethod
    def tearDownClass(cls):
        """
        Delete all VMs and the additional security group.
        """
        for vm in cls.default_group + cls.group2 + cls.other_vms:
            cls.delete_vm(vm.name)

        # Can't delete Sec group while VMs are using it, so give the VMs time
        # to disappear
        neutron = cls.controller.tenants["admin"].neutron
        retry_until_success(
            functools.partial(neutron.delete_security_group, cls.security_group["id"]),
            retries=60,
            context_string="%s.tearDownClass" % cls.__name__,
        )
        super(Topology2SecurityGroupsBase, cls).tearDownClass()

    def default_check_connectivity(self):
        """
        Test default connectivity for this topology.  Default group VMs should
        be able to ping each other, Group 2 VMs should be able to ping each
        other, but cannot ping between groups.
        """
        _log.info("Check correct connectivity within and between security groups")
        self.check_mutual_connectivity(
            pass_list=self.default_group, fail_list=self.group2
        )
        self.check_mutual_connectivity(
            pass_list=self.group2, fail_list=self.default_group
        )


class Topology2SecurityGroups(Topology2SecurityGroupsBase):
    """
    Setup an additional security group so we can test connectivity for
    VMs in different groups.
    """

    @classmethod
    def setUpClass(cls):
        super(Topology2SecurityGroups, cls).setUpClass()

        cls.default_group_image_type = CIRROS
        cls.group2_image_type = CIRROS
        # Ubuntu vms are expensive - we're only going to use CirrOS here.
        cls.max_number_of_ubuntu_vms_per_group = 0
        cls.add_random_vm = True

        _log.info("Running %s.setUpClass", cls.__name__)
        cls.security_group = cls.create_security_group_with_basic_rules("group2")

        cls.set_up_vms()


class Topology2SecurityGroupsUbuntu(Topology2SecurityGroupsBase):
    """
    Sets up a topology with two security groups, the first group using two
    Ubuntu VMs. See the base class for details.  Due to the memory
    requirements of Ubuntu VMs, we only add two, and disable the random VM
    """

    @classmethod
    def setUpClass(cls):
        super(Topology2SecurityGroupsUbuntu, cls).setUpClass()

        cls.default_group_image_type = IPV6_WITH_APPS
        cls.group2_image_type = CIRROS
        # Ubuntu VMs need more resources - this allows us to have the first couple of
        # VMs in a group as Ubuntu, but the rest as CirrOS
        cls.max_number_of_ubuntu_vms_per_group = 2
        cls.add_random_vm = False

        _log.info("Running %s.setUpClass", cls.__name__)
        _log.info("Creating security group: group2")
        cls.security_group = cls.create_security_group("group2")
        cls.add_ssh_rule("group2")
        cls.add_group_ping_rule("group2")

        cls.set_up_vms()


class TopologyUbuntuVm(Topology):
    """
    Sets up a basic setup with one Ubuntu VM
    """

    UBUNTU_GROUPNAME = "ubuntu_group"

    @classmethod
    def setUpClass(cls):
        super(TopologyUbuntuVm, cls).setUpClass()
        cls.create_security_group_with_basic_rules(cls.UBUNTU_GROUPNAME)
        _log.info("Running %s.setUpClass", cls.__name__)
        _log.info("Adding Ubuntu VM")
        cls.ubuntu_vm = cls.create_vm(
            availability_zone=LAYOUT.compute_nodes[0],
            security_groups=cls.UBUNTU_GROUPNAME,
            image=IPV6_WITH_APPS,
            ubuntu_speedup_sudo=True,
        )
        _log.info("Ubuntu VM created")


class TopologyTwoUbuntuVms(Topology):
    """
    Sets up a couple of Ubuntu VMs in parallel in a new security group
    """

    UBUNTU_GROUPNAME = "ubuntu_group"

    @classmethod
    def setUpClass(cls):
        _log.info("Running %s.setUpClass", cls.__name__)
        super(TopologyTwoUbuntuVms, cls).setUpClass()
        cls.vms = []

        def create_ubuntu_vm():
            new_vm = cls.create_vm(
                availability_zone=LAYOUT.compute_nodes[0],
                security_groups=cls.UBUNTU_GROUPNAME,
                image=IPV6_WITH_APPS,
                ubuntu_speedup_sudo=True,
            )
            cls.vms.append(new_vm)

        cls.create_security_group_with_basic_rules(cls.UBUNTU_GROUPNAME)
        _log.info("Adding Ubuntu VMs")
        threads = []
        for vm in range(2):
            thread = threading.Thread(target=create_ubuntu_vm)
            thread.daemon = True
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        _log.info("Ubuntu VMs created")


class TopologyBasicFloatingIPs(TopologyBasic):
    """
    Like TopologyBasic, plus what's needed to be able to assign floating IPs to
    the VMs.
    """

    @classmethod
    def setUpClass(cls):
        super(TopologyBasicFloatingIPs, cls).setUpClass()

        _log.info("Running %s.setUpClass", cls.__name__)
        cls.float_net = cls.create_network(
            FLOAT_IPV4.name, cidr=FLOAT_IPV4.cidr, router_external=True
        )

        neutron = cls.controller.tenants["admin"].neutron

        # Create a Neutron router.
        req = {"router": {"name": "router1", "admin_state_up": True}}
        rsp = neutron.create_router(req)
        _log.debug("Neutron rsp: %s", rsp)
        cls.router1 = rsp["router"]

        # Link it to the default network's IPv4 subnet.
        rsp = neutron.list_subnets()
        _log.debug("Neutron rsp: %s", rsp)
        subnets = rsp["subnets"]
        cls.router_interface_id = None
        for s in subnets:
            if (
                s["ip_version"] == 4
                and s["network_id"]
                == cls.controller.tenants["admin"].networks[DEFAULT_NET_NAME]
            ):
                cls.router_interface_id = s["id"]
                break
        assert cls.router_interface_id is not None
        req = {"subnet_id": cls.router_interface_id}
        rsp = neutron.add_interface_router(cls.router1["id"], req)
        _log.debug("Neutron rsp: %s", rsp)

        # Also link the router to the external floating IP network.
        req = {"network_id": cls.float_net}
        rsp = neutron.add_gateway_router(cls.router1["id"], req)
        _log.debug("Neutron rsp: %s", rsp)
        cls.router1 = rsp["router"]

    @classmethod
    def tearDownClass(cls):
        _log.info("Running %s.tearDownClass", cls.__name__)

        super(TopologyBasicFloatingIPs, cls).tearDownClass()

        neutron = cls.controller.tenants["admin"].neutron

        # Delete the router.
        req = {"subnet_id": cls.router_interface_id}
        rsp = neutron.remove_interface_router(cls.router1["id"], req)
        _log.debug("Neutron rsp: %s", rsp)
        rsp = neutron.delete_router(cls.router1["id"])
        _log.debug("Neutron rsp: %s", rsp)


class ServiceStateError(Exception):
    pass
