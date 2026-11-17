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

import functools
import logging
import sys
import time

from keystoneauth1 import identity
from keystoneauth1 import session
from keystoneclient.v2_0.client import Client as KeystoneClient
from keystoneclient.v3.client import Client as Keystone3Client
from neutronclient.common.exceptions import PortNotFoundClient
from neutronclient.v2_0.client import Client as NeutronClient
from novaclient.client import Client as NovaClient
from novaclient.exceptions import NotFound

from calicotest import settings
from calicotest.common.testutils import retry_until_success
from calicotest.openstack.config import LAYOUT
from calicotest.openstack.vm import Vm
from calicotest.settings import CIRROS, DEFAULT_NET_NAME, DEFAULT_NETS

_log = logging.getLogger(__name__)


DEFAULT = object()


class SystemCleanupException(Exception):
    pass


_default_net_by_region = {}


class Tenant(object):
    """
    A representation of an OpenStack Tenant.
    """

    def __init__(
        self,
        controller,
        name,
        password,
        host,
        test_machine_ip,
        user_id=None,
        tenant_id=None,
    ):
        self.controller = controller
        self.name = name
        self.password = password
        self.host = host
        self.auth = None
        self.session = None
        self.nova = None
        self.keystone = None
        self.keystone3 = None
        self.neutron = None
        self.id = tenant_id
        self.user_id = user_id
        self.images = None
        self.flavors = None
        self.availability_zones = None
        self.aggregates = None
        self.compute_hosts = None
        self.security_groups = None
        self.security_groups_creation = {}
        self.networks = None
        self.test_machine_ip = test_machine_ip
        self.vms = {}
        self.region = controller.region

    def cleanup_system(self):
        """
        Returns system to a known base state for running tests.
        Should only be run if this tenant is admin - and method will raise an
        exception if a non-admin tries to run it.
        :return: None
        """
        _log.info("Running cleanup_system")
        if self.name != "admin":
            _log.critical("Attempt to cleanup system by non-admin tenant!")
            raise SystemCleanupException(
                "Attempt to cleanup system by non-admin tenant!"
            )

        changes_made = False
        retry_until_success(self._check_hosts, 60)
        changes_made = self._normalise_aggregates() or changes_made

        # We need to delete leftover VMs before we can delete their networks
        changes_made = self._delete_leftovers() or changes_made
        changes_made = self._normalise_networks() or changes_made

        # Check Felix is started and etcd is unpaused on all nodes
        for compute in LAYOUT.compute_nodes:
            compute.start_felix()

        # Allow time for all the above to complete.
        if changes_made:
            # Aggregates and availability groups seem to be found and listable, but
            # when you try to use them to create a VM, it fails.  Presumably OpenStack
            # is temporarily inconsistent - this sleep lets the change propagate
            # through.
            _log.info("About to sleep for 3s to let OpenStack settle.")
            time.sleep(3)
            _log.info("Finished sleep. OpenStack should be stable now")
        self._update_admin_dicts()
        self._update_common_dicts()

    def connect(self):
        """
        Connects to the controller. Creates dictionaries of OpenStack objects.
        """
        _log.info("Connecting to %s as tenant %s", self.host, self.name)
        self._get_clients()

        if self.name == "admin":
            _log.info("admin user, updating admin-specific state")
            # Projects are only available in keystone v3 API.
            # We need the ID to be able to add security group rules (for example)
            for project in self.keystone3.projects.list():
                _log.info("Listed project %s", project)
                if project.name == "admin":
                    self.id = project.id
            _log.info("Storing id %s for 'admin' tenant", self.id)
            self._normalise_flavors()
            self._update_admin_dicts()
        self._update_common_dicts()

        # Make sure there is a rule to allow ssh from the test box.
        change_made = self.add_security_group_rule(
            "default",
            "tcp",
            from_port=22,
            to_port=22,
            cidr=self.test_machine_ip + "/32",
        )

        if change_made:
            # Allow time for all the above to complete.
            # Aggregates and availability groups seem to be found and listable, but
            # when you try to use them to create a VM, it fails.  Presumably OpenStack
            # is temporarily inconsistent - this sleep lets the change propagate
            # through.
            _log.info("About to sleep for 3s to let OpenStack settle.")
            time.sleep(3)
            _log.info("Finished sleep.  Should be connected to OpenStack.")

    def _get_clients(self):
        """
        Connect to the OpenStack controller by creating API clients for the
        main components.
        """
        _log.debug("Connecting to OpenStack APIs")
        if self.controller == LAYOUT.control_node:
            auth_url = "http://{}:5000/v3".format(LAYOUT.keystone_host)
        else:
            auth_url = "http://{}:5000/v3".format(self.controller.fqdn)
        if self.name == "admin":
            self.auth = identity.Password(
                auth_url=auth_url,
                username=self.name,
                password=self.password,
                project_name=self.name,
                project_domain_id="default",
                user_domain_id="default",
            )
        else:
            self.auth = identity.Password(
                auth_url=auth_url,
                username=self.name,
                password=self.password,
                user_domain_id="default",
            )
        self.session = session.Session(auth=self.auth)
        self.nova = NovaClient(2, session=self.session)

        self.keystone = KeystoneClient(session=self.session)
        self.keystone3 = Keystone3Client(session=self.session)

        self.neutron = NeutronClient(session=self.session)

    def _update_admin_dicts(self):
        """
        Creates dictionaries of OpenStack objects that only the admin tenant
        has access to.
        """
        _log.debug("Handling admin tenant")

        # Make up a dictionary of compute hosts
        self.compute_hosts = {}
        for compute_host in self.nova.hypervisors.list():
            _log.debug("Found compute host: %s", compute_host.service["host"])
            self.compute_hosts[compute_host.service["host"]] = compute_host

        # Make up a dictionary of availability zones
        self.availability_zones = {}
        for az in self.nova.availability_zones.list():
            _log.debug("Found availability zone: %s", az.zoneName)
            self.availability_zones[az.zoneName] = az

        # Make up a dictionary of aggregates
        self.aggregates = {}
        for aggregate in self.nova.aggregates.list():
            _log.debug("Found aggregate: %s", aggregate.name)
            self.aggregates[aggregate.name] = aggregate

    def _update_common_dicts(self):
        """
        Creates dictionaries of OpenStack objects for each tenant to access.
        """
        # Make up a dictionary of images
        self.images = {}
        for image in self.nova.glance.list():
            _log.debug("Found image: %s", image.name)
            self.images[image.name] = image

        # Make up a dictionary of flavors
        self.flavors = {}
        for flavor in self.nova.flavors.list():
            _log.debug("Found flavor: %s", flavor.name)
            self.flavors[flavor.name] = flavor

        # Make up a dictionary of security_groups
        self.security_groups = {}
        for security_group in self.neutron.list_security_groups(tenant_id=self.id)[
            "security_groups"
        ]:
            sg_name = security_group["name"]
            sg_id = security_group["id"]
            _log.info("Found security group: '%s', id %s", sg_name, sg_id)
            self.security_groups[sg_name] = security_group
            self.security_groups_creation[sg_name] = 0

        # Make up a dictionary of network names to IDs
        networks = {}
        for network in self.neutron.list_networks()["networks"]:
            _log.debug("Found network: %s", network["name"])
            networks[network["name"]] = network["id"]
        self.networks = networks

    def _normalise_networks(self):
        """
        Normalise the networks.  These scripts require the presence of
        a single network on the system, which has to have the settings
        (name, subnets, etc) defined by DEFAULT_NETS in settings.py
        """
        changes_made = False
        default_exists = False
        _log.info("Normalising networks.")
        # Delete them all *except* the DEFAULT_NET
        for network in self.neutron.list_networks()["networks"]:
            if network["name"] == DEFAULT_NET_NAME:
                default_exists = True
            else:
                _log.info("Deleting network: %s", network["name"])
                retry_until_success(
                    functools.partial(self.neutron.delete_network, network["id"])
                )
                changes_made = True

        # Create the DEFAULT_NET (if it doesn't exist already)
        if not default_exists:
            _log.info("Creating %s.", DEFAULT_NET_NAME)
            if self.region not in _default_net_by_region:
                _default_net_by_region[self.region] = DEFAULT_NETS[
                    len(_default_net_by_region)
                ]
            default_net = _default_net_by_region[self.region]
            retry_until_success(
                functools.partial(
                    self.controller.create_network,
                    DEFAULT_NET_NAME,
                    cidr=default_net.cidr,
                    cidr_v6=default_net.cidr_v6,
                )
            )
            changes_made = True
        return changes_made

    def _check_hosts(self):
        """
        Checks that all the expected hosts are known to Nova and alive.
        :return:
        """
        _log.info("Checking that all hosts are present in nova.")
        host_names = set()
        for h in self.nova.hypervisors.list():
            _log.info("Host %s found in nova's record: %r", h, h.__dict__)
            host_names.add(h.hypervisor_hostname.split(".")[0])
        for h in self.compute_hosts:
            assert h in host_names, "Host %s not found in nova's record." % h

    def _normalise_aggregates(self):
        """
        Normalize the aggregates for the compute hosts.  The default
        configuration of the calicotest OpenStack cluster has an aggregate X
        in availability group X just containing host X.
        """

        # Loop through each host - we expect a separate aggregation group
        # and availability zone for each. Start by removing hosts from the
        # availability group that should not be there.  We need to do this
        # first because you cannot add a host to more than one group.
        _log.info("Normalising host aggregates.")
        agg_updated = {}
        for host in self.compute_hosts:
            _log.info("Checking aggregate %s", host)
            agg_updated[host] = False
            agg = self.aggregates.get(host, None)
            if not agg:
                _log.info("Aggregate group not present")
                continue
            _log.info("Remove invalid hosts for aggregate %s", host)
            for agg_host in agg.hosts[:]:
                if agg_host != host:
                    _log.info("  - removing %s", agg_host)
                    agg.remove_host(agg_host)
                    agg_updated[host] = True

        # Now loop through again, creating any aggregation group that does not
        # exist and fixing up the availability group of any that do.
        for host in self.compute_hosts:
            _log.info("Checking aggregate %s", host)
            agg = self.aggregates.get(host, None)
            if not agg:
                _log.info("Creating aggregate")
                self.create_aggregate(host, [host], availability_zone=host)
                agg_updated[host] = True
                continue

            if agg.availability_zone != host:
                _log.info("Update availability zone")
                agg.update({"availability_zone": host})
                agg_updated[host] = True

            if host not in agg.hosts:
                _log.info("Adding host %s to aggregate %s", host, agg)
                agg.add_host(host)
                agg_updated[host] = True

        # For any agg group that we updated, wait until the corresponding
        # availability zone is present, and then update our list of zones.
        for host in self.compute_hosts:
            if agg_updated[host]:
                _log.info("Updating aggregate data for %s", host)
                self._check_availability_zone_present(host)
                self.aggregates[host].get()

        if any(agg_updated.values()):
            _log.info("Update internal availability zones data")
            self._update_availability_zones()
        _log.info("Finished normalising host aggregates.")

        return any(agg_updated.values())

    def _normalise_flavors(self):
        """
        Create the 2 flavors that the tests will use:
        +----+-----------+-------+------+-----------+-------+-----------+
        | ID | Name      |   RAM | Disk | Ephemeral | VCPUs | Is Public |
        +----+-----------+-------+------+-----------+-------+-----------+
        | 1  | m1.tiny   |   512 |    1 |         0 |     1 | True      |
        | 2  | m1.small  |  2048 |   20 |         0 |     1 | True      |
        """
        # Delete any 'm1.tiny' flavor that already exists.
        try:
            self.nova.flavors.find(name="m1.tiny").delete()
        except Exception:
            pass

        # Delete any 'm1.small' flavor that already exists.
        try:
            self.nova.flavors.find(name="m1.small").delete()
        except Exception:
            pass

        # Create standard m1.tiny flavor.
        self.nova.flavors.create("m1.tiny", 512, 1, 1)

        # Create standard m1.small flavor except with 4Gb disk instead of 2Gb, so
        # that it's big enough for the IPv6-enabled image (which needs about 3Gb).
        self.nova.flavors.create("m1.small", 2048, 1, 4)

    def delete_ports(self, network):
        """
        Deletes any stray ports on this network
        :param network:
        :return:
        """
        _log.info("Delete stray ports.")
        net_id = self.networks[network]
        ports = self.neutron.list_ports()["ports"]
        for port in ports:
            if net_id == port["network_id"]:
                _log.info("Delete stray port %s.", port["id"])
                try:
                    self.neutron.delete_port(port["id"])
                except PortNotFoundClient:
                    # Delete sometimes fails. Probably because the list still
                    # has some entries that are in the process of being
                    # deleted.
                    _log.info("Delete stray port failed %s.", port["id"])

    def _delete_leftovers(self):
        """
        Delete any found VMs or security groups. If there are any to
        start with, they were probably from previous testing.
        """
        # Clear out any VMs left on the system
        _log.info("Looking for left-over VMs from previous run.")
        changes_made = False
        for vm in self.nova.servers.list(search_opts={"all_tenants": 1}):
            changes_made = True
            _log.warning("Found left over VM: deleting %s", vm.name)
            try:
                self.nova.servers.delete(vm)
            except NotFound:
                _log.error("Can't delete VM %s - not found" % vm.name)

        # Clear out any non-default security groups.
        _log.info("Looking for left-over SGs from previous run.")
        found_sg = False
        for sg in self.neutron.list_security_groups(tenant_id=self.id)[
            "security_groups"
        ]:
            sg_name = sg["name"]
            sg_id = sg["id"]
            if sg_name != "default":
                _log.warning("Found left over security group: deleting %s", sg_name)

                def sg_delete():
                    self.neutron.delete_security_group(sg_id)

                retry_until_success(
                    sg_delete, retries=60, context_string="Tenant._normalise_aggregates"
                )
                changes_made = True
                found_sg = True
        if found_sg:
            # Nova caches the old SG, clear it out.
            _log.info("Deleted some SGs, clearing the cache.")
            self._get_clients()

        # Attempt to set the default number of rules and groups in nova.
        _log.info("Resetting quotas.")
        try:
            self.update_nova_quota(
                security_group_rules=settings.OPENSTACK_DEF_RULES,
                security_groups=settings.OPENSTACK_DEF_GROUPS,
            )
        except Exception as e:
            _log.warning("Unable to reset default nova quotas: %r", e)

        # Attempt to set the default number of rules and groups in neutron.
        try:
            self.update_neutron_quota(
                security_group_rule=settings.OPENSTACK_DEF_RULES,
                security_group=settings.OPENSTACK_DEF_GROUPS,
            )
        except Exception as e:
            _log.warning("Unable to reset default neutron quotas: %r", e)
        # Update these in case we've deleted anything.
        self._update_admin_dicts()
        self._update_common_dicts()
        _log.info("Finished reset.")
        return changes_made

    def delete(self):
        """
        Deletes this tenant (and user) from OpenStack.
        """
        user = self.keystone.users.get(self.user_id)
        user.delete()
        tenant = self.keystone.tenants.get(self.id)
        tenant.delete()

    def create_vm(
        self,
        name,
        image=CIRROS,
        flavor=None,
        security_groups="default",
        availability_zone=None,
        networks=DEFAULT,
        ubuntu_speedup_sudo=True,
    ):
        """
        Creates a VM by calling Nova.  And adds it to the dictionary of VMs on
        this tenant.

        :returns: the VM.
        """
        networks = [DEFAULT_NET_NAME] if networks is DEFAULT else networks
        if not flavor:
            flavor = image.flavor

        # Ensure security groups is a list and converted to the internal name.
        if not isinstance(security_groups, list):
            security_groups = [security_groups]
        security_groups = [self.security_groups[sg]["name"] for sg in security_groups]

        # Passes args to vm, substituting text names for nova client objects
        # where necessary.
        vm = Vm(
            self,
            name,
            image=image,
            flavor=self.flavors[flavor],
            security_groups=security_groups,
            availability_zone=availability_zone,
            net_names=networks,
            net_ids=[self.networks[network] for network in networks],
            ubuntu_speedup_sudo=ubuntu_speedup_sudo,
        )

        # If any of the security groups on the VM were created within the
        # last 30s, wait 30s more before creating the VM.
        current_time = time.time()
        new_sgs = any(
            current_time - self.security_groups_creation[sg] < 30
            for sg in security_groups
        )
        if new_sgs:
            _log.info("Wait 30s to ensure that security groups are there.")
            time.sleep(30)

        vm.create()

        self.vms[name] = vm
        return vm

    def delete_vm(self, name):
        """
        Deletes a VM by calling Nova.  And removes it from the dictionary of
        VMs on this tenant.

        :param name: string specifying the name of the VM to delete.
        """
        if name in self.vms:
            vm = self.vms.pop(name)
            vm.delete()
        else:
            _log.error("VM %s not in list - might already be deleted" % name)

    def create_tenant(
        self, username, password, description="Test tenant", project_parent_id=None
    ):
        """
        Checks to see if there is already a tenant with this name, and if not,
        uses this tenant to create it.  Note that this will not
        work unless this tenant is the admin tenant...
        Also creates a user to go with the tenant.

        :returns: a tuple of strings of the user name and tenant name.
        """
        # do stuff to find or create a tenant.
        tenant = None
        user = None
        try:
            for t in self.keystone3.projects.list():
                if username == t.name:
                    tenant = t
            if tenant is None:
                tenant = self.keystone3.projects.create(
                    username,
                    "default",
                    description=description,
                    enabled=True,
                    parent_id=project_parent_id,
                )

            for u in self.keystone3.users.list():
                if username == u.name:
                    user = u
            if user is None:
                user = self.keystone3.users.create(
                    username, domain="default", project=tenant.id, password=password
                )

            # Give this user the 'admin' role within its own project.
            admin_role = None
            for role in self.keystone3.roles.list():
                _log.info("role: %r", role)
                if role.name == "admin":
                    admin_role = role
                    break
            assert admin_role is not None, "Couldn't find 'admin' role"
            self.keystone3.roles.grant(admin_role, user=user, project=tenant)

        except Exception:
            _log.exception("Couldn't create tenant with Keystone v3 client")
            for t in self.keystone.tenants.list():
                if username == t.name:
                    tenant = t
            if tenant is None:
                tenant = self.keystone.tenants.create(
                    tenant_name=username, description=description, enabled=True
                )

            for u in self.keystone.users.list():
                if username == u.username:
                    user = u
            if user is None:
                user = self.keystone.users.create(
                    name=username, password=password, tenant_id=tenant.id
                )

        return user.id, tenant.id

    def delete_tenant(self, username):
        """
        Deletes a tenant and user. Will only work if this tenant is an admin.
        """
        returncode = True
        tenant = None
        user = None
        try:
            for t in self.keystone3.projects.list():
                if username == t.name:
                    tenant = t
            for u in self.keystone3.users.list():
                if username == u.name:
                    user = u
            try:
                self.keystone3.users.delete(user)
                self.keystone3.projects.delete(tenant)
            except Exception:
                _log.debug("hit exception: ", sys.exc_info()[0])
                returncode = False
        except Exception:
            _log.exception("Couldn't delete tenant with Keystone v3 client")
            for t in self.keystone.tenants.list():
                if username == t.name:
                    tenant = t
            for u in self.keystone.users.list():
                if username == u.username:
                    user = u
            try:
                user.delete()
                tenant.delete()
            except Exception:
                _log.debug("hit exception: ", sys.exc_info()[0])
                returncode = False

        return returncode

    def create_aggregate(self, name, host_list, availability_zone=None):
        """
        Creates a new host aggregate.  Will only work if this tenant is an
        admin.
        """
        _log.info(
            "Creating a host aggregate called %s from hosts %s AZ=%s",
            name,
            host_list,
            availability_zone,
        )
        if availability_zone is None:
            _log.debug("Using availability zone based on name: %s", name)
            availability_zone = name

        agg = self.nova.aggregates.create(name, availability_zone)
        self.aggregates[name] = agg
        for host in host_list:
            agg.add_host(host)

        # Check the availability zone is now present
        self._check_availability_zone_present(availability_zone)

        # Make nova client update the aggregate object before passing back
        agg.get()

        # Update the availability zones.
        self._update_availability_zones()

        return agg

    def update_aggregate(self, name, host_list=None, availability_zone=None):
        """
        Update an aggregate with the new host list and availability zone.

        :param name:  The name of the aggregate group
        :param host_list:  The host list, or None if it is not to be updated
        :param availability_zone: The availability zone, or None if it is not
        to be updated.
        """
        agg = self.aggregates[name]
        if availability_zone is not None:
            agg.update({"availability_zone": availability_zone})
        if host_list is not None:
            for host in agg.hosts[:]:
                if host not in host_list:
                    agg.remove_host(host)
            for host in host_list:
                if host not in agg.hosts:
                    agg.add_host(host)
                self._check_availability_zone_present(host)
        agg.get()
        self._update_availability_zones()

    def _update_availability_zones(self):
        """
        Update the internal list of availability zones after performing an
        action that may have altered the list.
        """
        # Update availability zones: the actions above may have added one.
        for az in self.nova.availability_zones.list():
            self.availability_zones[az.zoneName] = az

    def _check_availability_zone_present(self, availability_zone):
        """
        Checks that the supplied zone is now registering on the OpenStack
        API.

        :param availability_zone: The availability zone to check.
        """

        def func():
            zones = self.nova.availability_zones.list()
            for az in zones:
                if az.zoneName == availability_zone:
                    _log.info("Availability zone %s present: %s", availability_zone, az)
                    return

            _log.warn("Availability zone %s not found", availability_zone)
            raise AssertionError("Availability zone %s not found" % availability_zone)

        _log.info("Checking availability zone %s is present", availability_zone)
        retry_until_success(
            func, retries=3, context_string="Tenant._check_availability_zone_present"
        )

    def add_security_group_rule(
        self,
        parent_groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidr=None,
        permitted_groupname=None,
        update_cache=True,
        direction="ingress",
        ethertype="IPv4",
    ):
        """
        Calls neutron to create a security group rule in OpenStack.
        There are 2 types of rule expected in here:
        1) rules for groups (e.g. where you say that all VMs in 'that'
        security group can contact VMs in 'this' group)
        2) rules of IP address ranges (e.g. where you say that this IP address
        (or range) can contact VMs in this security group).
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
        will be affected by this rule - cidr must be None if this is set
        :param update_cache: Whether we need to update our cache to resync
        the group data after updates.  Set to False if making a large number
        of updates to a group, and set to True on the last update.
        :param direction: Either 'ingress' or 'egress', depending on whether
        this rule should apply to incoming or outgoing traffic.
        :param ethertype: 'IPv4' for rules appling to IPv4 traffic, 'IPv6'
        for rules applying to IPv6 traffic.
        """
        _log.info("Add security group rule to %s", parent_groupname)
        parent_group = self.security_groups[parent_groupname]
        group_creation = self.security_groups_creation[parent_groupname]
        _log.info("Found group: %s", parent_group)

        changes_made = []

        def add_rule():
            if permitted_groupname is not None:
                # This is a rule involving groups
                assert cidr is None
                permitted = self.security_groups[permitted_groupname]
                # check if there is a rule like this already:
                # ... and create it if not
                if not any(
                    x["port_range_min"] == from_port
                    and x["port_range_max"] == to_port
                    and x["direction"] == direction
                    and x["protocol"] == proto
                    and x["remote_group_id"] == permitted["id"]
                    for x in parent_group["security_group_rules"]
                ):
                    _log.debug("Adding RULE with:")
                    _log.debug("ip_proto=%s", proto)
                    _log.debug("from_port=%s", from_port)
                    _log.debug("to_port=%s", to_port)
                    _log.debug("group_id=%s", permitted["id"])
                    body = {
                        "security_group_rule": {
                            "security_group_id": parent_group["id"],
                            "direction": direction,
                            "protocol": proto,
                            "port_range_min": from_port,
                            "port_range_max": to_port,
                            "remote_group_id": permitted["id"],
                            "ethertype": ethertype,
                        }
                    }
                    self.neutron.create_security_group_rule(body)
                    changes_made.append(True)
            else:
                # This is a rule involving IP addresses, etc.
                assert permitted_groupname is None
                # check if there is a rule like this already:
                # ... and create it if not
                if not any(
                    x["port_range_min"] == from_port
                    and x["port_range_max"] == to_port
                    and x["direction"] == direction
                    and x["protocol"] == proto
                    and x["remote_ip_prefix"] == cidr
                    for x in parent_group["security_group_rules"]
                ):
                    _log.debug("Adding RULE with:")
                    _log.debug("ip_proto=%s", proto)
                    _log.debug("from_port=%s", from_port)
                    _log.debug("to_port=%s", to_port)
                    _log.debug("cidr=%s", cidr)
                    body = {
                        "security_group_rule": {
                            "security_group_id": parent_group["id"],
                            "direction": direction,
                            "protocol": proto,
                            "port_range_min": from_port,
                            "port_range_max": to_port,
                            "remote_ip_prefix": cidr,
                            "ethertype": ethertype,
                        }
                    }
                    _log.debug("Creating group rule, body=%s", body)
                    self.neutron.create_security_group_rule(body)
                    changes_made.append(True)

        # If the security group was newly created, allow retries because
        # OpenStack can be a little sluggish in propagating new group info.
        if time.time() - group_creation < 30:
            retry_until_success(
                add_rule, context_string="Tenant.add_security_group_rule"
            )
        else:
            add_rule()

        # Update our cache.
        if parent_group and update_cache:
            _log.debug("Update cache")
            group_id = parent_group["id"]
            group = self.neutron.show_security_group(group_id)["security_group"]
            _log.info("GROUP = %r", group)
            assert group["id"] == group_id
            assert group["name"] == str(parent_groupname)
            self.security_groups[parent_groupname] = group
            _log.info("Updated group: %s", parent_groupname)
            _log.info(" - id=%s", group["id"])
            for rule in group["security_group_rules"]:
                _log.info(" - RULE %s", rule)

        return bool(changes_made)

    def add_security_group_rules(
        self,
        parent_groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidrs=None,
        permitted_groupname=None,
        update_cache=True,
        direction="ingress",
        ethertype="IPv4",
    ):
        _log.info("Add security group rules to %s", parent_groupname)
        parent_group = self.security_groups[parent_groupname]
        group_creation = self.security_groups_creation[parent_groupname]
        _log.info("Found group: %s", parent_group)

        changes_made = []

        def add_rules():
            # This is a rule involving IP addresses, etc.
            assert permitted_groupname is None
            # check if there is a rule like this already:
            # ... and create it if not
            if not any(
                x["port_range_min"] == from_port
                and x["port_range_max"] == to_port
                and x["direction"] == direction
                and x["protocol"] == proto
                and x["remote_ip_prefix"] in cidrs
                for x in parent_group["security_group_rules"]
            ):
                _log.debug("Adding RULES with:")
                _log.debug("ip_proto=%s", proto)
                _log.debug("from_port=%s", from_port)
                _log.debug("to_port=%s", to_port)
                body = {
                    "security_group_rules": [
                        {
                            "security_group_id": parent_group["id"],
                            "direction": direction,
                            "protocol": proto,
                            "port_range_min": from_port,
                            "port_range_max": to_port,
                            "remote_ip_prefix": cidr,
                            "ethertype": ethertype,
                        }
                        for cidr in cidrs
                    ],
                }
                self.neutron.create_security_group_rule(body)
                changes_made.append(True)

        # If the security group was newly created, allow retries because
        # OpenStack can be a little sluggish in propagating new group info.
        if time.time() - group_creation < 30:
            retry_until_success(
                add_rules, context_string="Tenant.add_security_group_rule"
            )
        else:
            add_rules()

        # Update our cache.
        if parent_group and update_cache:
            _log.debug("Update cache")
            group_id = parent_group["id"]
            group = self.neutron.show_security_group(group_id)["security_group"]
            _log.info("GROUP = %r", group)
            assert group["id"] == group_id
            assert group["name"] == str(parent_groupname)
            self.security_groups[parent_groupname] = group
            _log.info("Updated group: %s", parent_groupname)
            _log.info(" - id=%s", group["id"])
            for rule in group["security_group_rules"]:
                _log.info(" - RULE %s", rule)

        return bool(changes_made)

    def get_security_group(self, parent_groupname):
        """
        Returns a security group object matching the name given if it exists.  We get
        the id from our cached store, which has been got from Nova, because Neutron
        has been seen to return multiple default security groups; this way we get the
        security group that is shown in Horizon.
        :param parent_groupname: The name of the group to search for
        """
        try:
            group_id = self.security_groups[parent_groupname]["id"]
            _log.info("Get SG '%s', id %s", parent_groupname, group_id)
        except KeyError:
            group_id = None
        try:
            sgs = self.neutron.list_security_groups(tenant_id=self.id)[
                "security_groups"
            ]
            for group in sgs:
                _log.info("Listed SG: %s", group)
            parent_group = [group for group in sgs if group["id"] == group_id][0]
        except IndexError:
            parent_group = None
        return parent_group

    def delete_security_group_rule(
        self,
        parent_groupname,
        proto=None,
        from_port=None,
        to_port=None,
        cidr=None,
        permitted_groupname=None,
        update_cache=True,
        direction="ingress",
        ethertype="IPv4",
    ):
        """
        Calls neutron to delete a security group rule.
        :param parent_groupname: The name of the group the rule should be
        deleted from.
        :param proto: The ip protocol that the rule applies to. Set to None
        to apply to any protocol
        :param from_port: The start of the port range this rule should apply
        to - set to None for any.  Applies to UDP and TCP - for ICMP this will
        refer to the message type allowed.
        :param to_port: The end of the port range this rule should apply to -
        set to None for any
        :param cidr: The ip address block the rule applies to.  If this is set
        permitted_groupname must be None.
        :param permitted_groupname: If set, traffic to/from this security group
        will be affected by this rule - cidr must be None if this is set
        :param update_cache: Whether we need to update our cache to resync
        the group data after updates.  Set to False if making a large number
        of updates to a group, and set to True on the last update.
        :param direction: Either 'ingress' or 'egress', depending on whether
        this rule should apply to incoming or outgoing traffic.
        :param ethertype: 'IPv4' for rules appling to IPv4 traffic, 'IPv6'
        for rules applying to IPv6 traffic.
        """
        _log.info("Delete security group rule from %s", parent_groupname)
        parent_group = self.get_security_group(parent_groupname)
        if parent_group is None:
            # We didn't find the requested group
            _log.info("Did not find group: %s", parent_groupname)
            return

        _log.info("Found group: %s", parent_group)
        for rule in parent_group["security_group_rules"]:
            _log.info("Check rule: %s", rule)
            # If any of these don't match then this can't be our rule so skip
            # to the next one
            if (
                rule["port_range_min"] != from_port
                or rule["port_range_max"] != to_port
                or rule["protocol"] != proto
                or rule["direction"] != direction
                or rule["ethertype"] != ethertype
            ):
                _log.info(
                    "Does not match args given.  from_port=%s, "
                    "to_port=%s, ip_protocol=%s, direction=%s, "
                    "ethertype=%s",
                    from_port,
                    to_port,
                    proto,
                    direction,
                    ethertype,
                )
                continue

            if permitted_groupname is not None:
                # This must be a rule involving groups
                permitted_group = self.get_security_group(permitted_groupname)
                if permitted_group is None:
                    # We didn't find the requested group
                    _log.info("Did not find group: %s", permitted_groupname)
                    return
                assert cidr is None
                if rule["tenant_id"] != self.id:
                    _log.info(
                        "Rule's tenant %s does not match current tenant %s",
                        rule["tenant_id"],
                        self.id,
                    )
                    continue
                if rule["remote_group_id"] != permitted_group["id"]:
                    _log.info(
                        "Rule's remote group %s does not match '%s' id %s",
                        rule["remote_group_id"],
                        permitted_groupname,
                        permitted_group["id"],
                    )
                    continue
            elif cidr is not None:
                # This must be a rule involving IP ranges
                assert permitted_groupname is None
                if rule["remote_ip_prefix"] != cidr:
                    _log.info("Does not match IP range %s", cidr)
                    continue
            else:
                # This is a very permissive rule
                if (
                    rule["remote_ip_prefix"] is not None
                    or rule["remote_group_id"] is not None
                ):
                    continue

            # If we get this far, we've found our rule, so delete it.
            _log.info("Deleting security group rule")
            self.neutron.delete_security_group_rule(rule["id"])

            # Update our cache.
            if parent_group and update_cache:
                _log.info("Update cache")
                self.security_groups[parent_groupname] = (
                    self.neutron.show_security_group(parent_group["id"])[
                        "security_group"
                    ]
                )
                _log.info("Updated group: %s", self.security_groups[parent_groupname])
            break
        else:
            _log.info("Could not find rule to delete, carrying on anyway")

    def create_security_group(self, name, description):
        """
        Checks if a security group is in the tenant's dictionary.  If not,
        calls to neutron to add it.
        """
        if name not in self.security_groups:
            group = self.neutron.create_security_group(
                body={
                    "security_group": {
                        "name": name,
                        "description": description,
                    },
                }
            )["security_group"]
            self.security_groups[name] = group
            self.security_groups_creation[name] = time.time()
            _log.info("Created SG '%s', id %s", name, group["id"])
        else:
            group = self.security_groups[name]
        return group

    def delete_security_group(self, name):
        """
        Calls neutron to delete a security group.
        """
        group = self.security_groups.pop(name)
        _log.info("Deleting SG '%s', id %s", name, group["id"])
        self.security_groups_creation.pop(name)
        self.neutron.delete_security_group(group["id"])

    def update_nova_quota(self, **kwargs):
        """
        Exposes nova function to change quota values.
        """
        self.nova.quotas.update(self.id, **kwargs)

    def update_neutron_quota(self, **kwargs):
        """
        Exposes neutron function to change quota values.
        """
        self.neutron.update_quota(self.id, {"quota": kwargs})
