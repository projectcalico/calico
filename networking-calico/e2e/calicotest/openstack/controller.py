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

import logging

from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.tenant import Tenant
from calicotest.settings import CIRROS, DEFAULT_NET_NAME

_log = logging.getLogger(__name__)


class Controller(object):
    """
    A representation of the OpenStack controller.

    Stores:

    - nova clients for doing stuff on the controller
    - dictionaries of nova_objects so we can translate from string names
      to nova objects when making calls to nova client.
    """

    def __init__(
        self,
        fqdn,
        shell_username,
        shell_password,
        admin_password,
        test_machine_ip,
        region=None,
    ):
        self.ssh = None
        self.fqdn = fqdn
        self.test_machine_ip = test_machine_ip
        self.rebooting = False
        self.region = region

        admin_tenant = Tenant(self, "admin", admin_password, fqdn, test_machine_ip)
        admin_tenant.connect()
        # Make up a dictionary of Tenants.
        self.tenants = {"admin": admin_tenant}
        self.ssh = LAYOUT.control_node

    def can_connect(self, retries=60):
        """
        Check it is possible to SSH in to the controller.
        """
        retry_until_success(
            self.ssh.connect, retries=retries, context_string="Controller.can_connect"
        )
        self.ssh.disconnect()
        self.rebooting = False

    def execute(self, command):
        """
        Runs a command over the ssh session to the controller (set up
        previously).
        """
        with self.ssh:
            return self.ssh.execute(command)

    def reboot(self, wait_for_ssh_to_fail=True):
        """
        Issue a sudo reboot to the host.  It assumes the host has passwordless
        sudo access.

        If wait_for_ssh_to_fail is True, it waits for restart to complete before
        returning.

        Once rebooted, use the can_connect method to wait until the server
        has finished rebooting.

        Note that any connectivity testing performed during a reboot will use
        cached interface information (see get_all_addresses in vm.py).  Any
        other nova or neutron actions cannot be expected to succeed during
        the reboot.

        :param wait_for_ssh_to_fail: Wait for the server to restart
        """
        with self.ssh:
            self.rebooting = True
            self.ssh.reboot(wait_for_restart=False)
            if wait_for_ssh_to_fail:
                retry_until_success(
                    self.ssh.assert_connection_dead,
                    retries=60,
                    context_string="Controller.reboot",
                )

    def get_vms(self, tenant="admin"):
        """
        Returns a list of VMs from Nova client.
        """
        return self.tenants[tenant].nova.servers.list()

    def create_aggregate(self, name, host_list, availability_zone=None, tenant="admin"):
        """
        Creates an aggregate.
        """
        return self.tenants[tenant].create_aggregate(
            name, host_list, availability_zone=availability_zone
        )

    def create_vm(
        self,
        name,
        tenant="admin",
        image=CIRROS,
        flavor=None,
        security_groups="default",
        availability_zone=None,
        networks=[DEFAULT_NET_NAME],
        ubuntu_speedup_sudo=False,
    ):
        """
        Creates a VM.
        """
        if not flavor:
            flavor = image.flavor
        # Note that we get availability zones from 'admin' because only they
        # can see them
        av_zone = self.tenants["admin"].availability_zones.get(availability_zone)
        vm = self.tenants[tenant].create_vm(
            name,
            image=image,
            flavor=flavor,
            security_groups=security_groups,
            availability_zone=av_zone,
            networks=networks,
            ubuntu_speedup_sudo=ubuntu_speedup_sudo,
        )
        return vm

    def delete_vm(self, vm_name, tenant="admin"):
        """
        Deletes a VM.
        """
        self.tenants[tenant].delete_vm(vm_name)

    def create_tenant(
        self, name, password="password", creator="admin", project_parent_id=None
    ):
        """
        Creates a tenant (and a user to go with it).
        """
        user_id, tenant_id = self.tenants[creator].create_tenant(
            name, password, project_parent_id=project_parent_id
        )
        tenant = Tenant(
            self,
            name,
            password,
            self.fqdn,
            self.test_machine_ip,
            user_id=user_id,
            tenant_id=tenant_id,
        )
        tenant.connect()
        _log.info("Tenant connected.  Adding to tenants dict")
        self.tenants[name] = tenant

        return tenant

    def delete_tenant(self, name, tenant="admin"):
        """
        Deletes a tenant (and its associated user).
        """
        if self.tenants[tenant].delete_tenant(name):
            self.tenants.pop(name)

    def create_network(
        self, name, cidr=None, cidr_v6=None, tenant="admin", router_external=False
    ):
        """
        Creates a network.
        One or both of cidr or cidr_v6 must be specified.
        """
        assert cidr is not None or cidr_v6 is not None

        if name not in self.tenants[tenant].networks:
            body_sample = {
                "network": {
                    "name": name,
                    "admin_state_up": True,
                    "shared": True,
                    "router:external": router_external,
                }
            }
            network = self.tenants[tenant].neutron.create_network(body=body_sample)
            network_id = network["network"]["id"]
            if cidr is not None:
                body = {
                    "subnets": [
                        {
                            "cidr": cidr,
                            "ip_version": 4,
                            "network_id": network_id,
                            "dns_nameservers": ["8.8.8.8"],
                        }
                    ]
                }
                self.tenants[tenant].neutron.create_subnet(body=body)
            if cidr_v6 is not None:
                # We need dhcpv6-stateful set to have working IPv6.
                body = {
                    "subnets": [
                        {
                            "cidr": cidr_v6,
                            "ip_version": 6,
                            "network_id": network_id,
                            "ipv6_address_mode": "dhcpv6-stateful",
                        }
                    ]
                }
                self.tenants[tenant].neutron.create_subnet(body=body)
        else:
            network_id = self.tenants[tenant].networks[name]

        self.tenants[tenant].networks[name] = network_id

        return network_id

    def delete_network(self, net_name, tenant="admin"):
        """
        Deletes a network.
        """
        network_id = self.tenants[tenant].networks[net_name]
        self.tenants[tenant].neutron.delete_network(network_id)
        self.tenants[tenant].networks.pop(net_name)

    def create_security_group(self, name, description="", tenant="admin"):
        """
        Checks if a security group is in the tenant's dictionary.  If not,
        get the tenant to add it.
        """
        return self.tenants[tenant].create_security_group(name, description)

    def delete_security_group(self, name, tenant="admin"):
        """
        Deletes a security group
        """
        assert name in self.tenants[tenant].security_groups
        self.tenants[tenant].delete_security_group(name)

    def add_security_group_rule(
        self,
        parent_groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidr=None,
        permitted_groupname=None,
        tenant="admin",
        update_cache=True,
        direction="ingress",
        ethertype="IPv4",
    ):
        """
        Adds a rule to a security group.

        :param parent_groupname: The name of the group the rule should be
                                 added to.
        :param proto: The ip protocol that the rule applies to. Set to None
                      to apply to any protocol
        :param from_port: The start of the port range this rule should apply
                          to - set to None for any.
        :param to_port: The end of the port range this rule should apply to -
                        set to None for any
        :param cidr: The ip address block the rule applies to.  If this is set
                     permitted_groupname must be None.
        :param permitted_groupname: If set, traffic to/from this security group
                                    will be affected by this rule - cidr must
                                    be None if this is set
        :param tenant: The tenant who the rule will apply to
        :param update_cache: Whether we need to update our cache to resync
                             the group data after updates.  Set to False if
                             making a large number of updates to a group, and
                             set to True on the last update.
        :param direction: Either 'ingress' or 'egress', depending on whether
                          this rule should apply to incoming or outgoing
                          traffic.
        :param ethertype: 'IPv4' for rules appling to IPv4 traffic, 'IPv6'
                          for rules applying to IPv6 traffic.
        """
        self.tenants[tenant].add_security_group_rule(
            parent_groupname,
            proto=proto,
            from_port=from_port,
            to_port=to_port,
            cidr=cidr,
            permitted_groupname=permitted_groupname,
            update_cache=update_cache,
            direction=direction,
            ethertype=ethertype,
        )

    def add_security_group_rules(
        self,
        parent_groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidrs=None,
        permitted_groupname=None,
        tenant="admin",
        update_cache=True,
        direction="ingress",
        ethertype="IPv4",
    ):
        self.tenants[tenant].add_security_group_rules(
            parent_groupname,
            proto=proto,
            from_port=from_port,
            to_port=to_port,
            cidrs=cidrs,
            permitted_groupname=permitted_groupname,
            update_cache=update_cache,
            direction=direction,
            ethertype=ethertype,
        )

    def delete_security_group_rule(
        self,
        parent_groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidr=None,
        permitted_groupname=None,
        tenant="admin",
        update_cache=True,
        direction="ingress",
        ethertype="IPv4",
    ):
        """
        Deletes a rule from a security group matching the criteria set, if it
        exists.

        :param parent_groupname: The name of the group the rule should be
        deleted from.
        :param proto: The ip protocol that the rule applies to. Set to None
        to apply to any protocol
        :param from_port: The start of the port range this rule should apply
        to - set to None for any.
        :param to_port: The end of the port range this rule should apply to -
        set to None for any
        :param cidr: The ip address block the rule applies to.  If this is set
        permitted_groupname must be None.
        :param permitted_groupname: If set, traffic to/from this security group
        will be affected by this rule - cidr must be None if this is set
        :param tenant: The tenant who the rule will apply to
        :param update_cache: Whether we need to update our cache to resync
        the group data after updates.  Set to False if making a large number
        of updates to a group, and set to True on the last update.
        :param direction: Either 'ingress' or 'egress', depending on whether
        this rule should apply to incoming or outgoing traffic.
        :param ethertype: 'IPv4' for rules appling to IPv4 traffic, 'IPv6'
        for rules applying to IPv6 traffic.
        """
        self.tenants[tenant].delete_security_group_rule(
            parent_groupname,
            proto=proto,
            from_port=from_port,
            to_port=to_port,
            cidr=cidr,
            permitted_groupname=permitted_groupname,
            update_cache=update_cache,
            direction=direction,
            ethertype=ethertype,
        )

    def update_nova_quota(self, **kwargs):
        """
        Exposes nova function to change quota values.
        """
        self.tenants["admin"].update_nova_quota(**kwargs)

    def update_neutron_quota(self, **kwargs):
        """
        Exposes neutron function to change quota values.
        """
        self.tenants["admin"].update_neutron_quota(**kwargs)
