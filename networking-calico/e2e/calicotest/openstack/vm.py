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

import itertools
import logging
import time

import netaddr
from novaclient.exceptions import NotFound

from calicotest.common.ssh import SSH
from calicotest.common.testutils import retry_until_success
from calicotest.settings import CIRROS

_log = logging.getLogger(__name__)


class WrongState(RuntimeError):
    pass


class VmErrorState(AssertionError):
    pass


class Vm(object):
    """
    A representation of an OpenStack VM.

    Stores:

    - details of VM (name, ip, tenant, network, etc, etc)
    - which compute host it is on (availability_zone)
    - the Nova Client representation of the VM (if any)
    - a connection to the VM (for running commands on it)

    Note the ubuntu_speedup_sudo flag, allows you to use sudo on the vm without
    ~10second delay every time you run a sudo command, at the cost of bootup
    being ~10 seconds slower. Set it to true if you create an ubuntu vm that
    you will need to run commands as sudo on!
    """

    def __init__(
        self,
        tenant,
        name,
        image,
        flavor,
        security_groups,
        availability_zone,
        net_names,
        net_ids,
        ubuntu_speedup_sudo=False,
    ):

        super(Vm, self).__init__()
        self.vm = None
        self.name = name
        self.image = image
        self.flavor = flavor
        self.availability_zone = availability_zone
        self.net_names = net_names
        self.net_ids = net_ids
        self.security_groups = security_groups
        self.tenant = tenant
        self.ssh = None
        self.cached_interfaces = None
        self.ubuntu_speedup_sudo = ubuntu_speedup_sudo

    def __str__(self):
        try:
            my_id = self.vm.to_dict()["id"]
            ips = [str(i) for i in self.get_all_addresses() or []]
        except (KeyError, AttributeError):
            my_id = "<unknown>"
            ips = "<unknown>"
        return self.__class__.__name__ + "<%s(%s),%s,%s,%s,%s>" % (
            self.name,
            my_id,
            self.image and self.image.name,
            self.availability_zone and self.availability_zone.zoneName,
            self.security_groups,
            ips,
        )

    def create(self):
        """
        Calls nova client to create the VM in OpenStack.  Stores the nova
        client object in self.vm as well as passing it back.

        :returns: the nova client object.
        """
        assert self.vm is None
        image = self.tenant.images[self.image.name]

        # command = "nova boot {name} --flavor {flavor} image {image}
        # security-groups {security_group} --nic net-id={network}
        # --availability-zone nova:{compute_host}".format(.....
        # controller.execute(command)
        _log.info(
            "Try to create VM: %s",
            {
                "name": self.name,
                "image": image,
                "flavor": self.flavor,
                "security_groups": self.security_groups,
                "availability_zone": self.availability_zone
                and self.availability_zone.zoneName,
                "nics": [{"net-id": net_id} for net_id in self.net_ids],
            },
        )
        self.vm = self.tenant.nova.servers.create(
            self.name,
            image,
            self.flavor,
            security_groups=self.security_groups,
            availability_zone=self.availability_zone
            and self.availability_zone.zoneName,
            nics=[{"net-id": net_id} for net_id in self.net_ids],
        )

        vm_reached_active = False
        try:
            # Wait for the VM to reach ACTIVE state.
            self.wait_for_state(
                "ACTIVE", wait_time=7, retries=self.image.active_time / 7 + 1
            )
            _log.info("Successfully created VM: %s", self.vm.name)
            _log.info("    VM details: %s", self.vm.to_dict())
            vm_reached_active = True
            retry_until_success(
                self.connect, retries=self.image.boot_time, context_string="Vm.create"
            )
            if self.ubuntu_speedup_sudo:
                self.speedup_sudo_on_ubuntu()
        except Exception:
            _log.info("Failed to connect to VM: %s, deleting it...", self.vm.name)
            # Try to give more information if available.
            try:
                _log.info("    Failed VM details: %s", self.vm.to_dict())
            except Exception:
                pass
            try:
                if vm_reached_active:
                    _log.info(
                        "    Failed VM console log:\n%s", self.vm.get_console_output()
                    )
            except Exception:
                pass
            self.delete()
            raise
        else:
            _log.info("Successfully connected to VM: %s", self.vm.name)
            return self.vm

    def delete(self):
        """
        Calls nova client to delete the VM from OpenStack.
        """
        _log.info("Deleting VM: %s", self.name)
        if self.ssh:
            self.ssh.disconnect()
            self.ssh = None
        self.tenant.nova.servers.delete(self.vm)
        delay = 0.1
        while True:
            try:
                status = self.get_current_status()
            except NotFound:
                _log.info("VM gone: %s", self.name)
                break
            else:
                _log.info("VM still present: %s (status %s)", self.name, status)
                if delay > 30:
                    _log.error("Failed to wait for VM to disappear")
                    raise Exception("Failed to wait for VM to disappear")
                time.sleep(delay)
                delay *= 2
        self.vm = None

    def connect(self, interface=0, ipv6=False):
        """
        Sets up an ssh connection to this VM to allow test commands to be sent
        to it later.
        """
        if self.ssh:
            return

        entries = self.vm.interface_list()[interface].fixed_ips
        ips = [netaddr.IPAddress(entry["ip_address"]) for entry in entries]
        ipv4_addrs = [ip for ip in ips if ip.version == 4]
        ipv6_addrs = [ip for ip in ips if ip.version == 6]

        if ipv6:
            assert (
                len(ipv6_addrs) == 1
            ), "Expected a single IPv6 address, found %s" % len(ipv6_addrs)
            ip = ipv6_addrs[0]
        else:
            assert (
                len(ipv4_addrs) == 1
            ), "Expected a single IPv4 address, found %s" % len(ipv4_addrs)
            ip = ipv4_addrs[0]

        _log.debug("Attempting to connect to %s", str(ip))
        ssh = SSH(
            str(ip),
            self.image.username,
            self.image.password,
            desc="%s on %s"
            % (
                self.image.name,
                self.availability_zone and self.availability_zone.zoneName,
            ),
        )
        ssh.connect()
        self.ssh = ssh

    def execute(self, command):
        """
        Runs a command on a VM.

        :param command: String containing the command to run on this VM
        :returns: exit status, stdout, stderr
        """
        if self.ssh is None:
            self.connect()
        return self.ssh.execute(command)

    def get_current_status(self):
        """
        Updates the novaclient object and returns the nova status string.
        """
        self.vm.get()
        return self.vm.status

    def pause(self):
        """
        Pauses a VM.
        """
        self.vm.pause()

    def unpause(self):
        """
        Unpauses a VM.
        """
        self.vm.unpause()
        self.restarted()

    def suspend(self):
        """
        Suspends a VM.
        """
        self.vm.suspend()

    def resume(self):
        """
        Resumes a VM which has been suspended
        """
        self.vm.resume()
        self.restarted()

    def start(self):
        """
        Starts a VM which has been stopped (or shutdown via CLI)
        """
        self.vm.start()
        self.restarted()

    def stop(self):
        """
        Stops a VM via Nova
        """
        self.vm.stop()

    def reboot(self, reboot_type="SOFT"):
        """
        Reboots a VM.

        :param reboot_type:  The reboot type.  Defaults to "SOFT".
        """
        self.vm.reboot(reboot_type)
        self.restarted()

    def add_security_group(self, groupname):
        """
        Adds a security group to this VM.

        :param groupname: the name of the security group to add to this VM
        """
        if groupname not in self.security_groups:
            _log.info("Add SG '%s' to VM %s", groupname, self.name)
            self.vm.add_security_group(groupname)
            self.security_groups.append(groupname)

    def remove_security_group(self, groupname):
        """
        Deletes a security group from this VM.

        :param groupname: the name of the security group to delete from this VM
        """
        _log.info("Remove SG '%s' from VM %s", groupname, self.name)
        self.vm.remove_security_group(groupname)
        self.security_groups.remove(groupname)

    def rebuild(self, image_id=None):
        """
        Triggers a rebuild of a VM using the image specified (defaults to using
        the image the VM was created with.)

        :param image_id: the id of the image to rebuild the VM with.
        """
        if image_id is None:
            image_id = self.vm.image["id"]
        self.vm.rebuild(image_id)
        self.restarted()

    def migrate(self):
        """
        Trigger a non-live migration of the VM.  This will select another
        host in the same availability zone.
        """
        self.vm.migrate()
        self.wait_for_state("VERIFY_RESIZE", retries=self.image.active_time)
        if self.ssh:
            assert not self.ssh.still_connected, "SSH is still connected"

        # Confirm the resize to complete the migration.
        self.vm.confirm_resize()

        # Since the VM has restarted, notify the SSH helper that a reconnect
        # is required.
        if self.ssh:
            self.ssh.restarted()

    def live_migrate(self, host=None, block_migration=False, disk_over_commit=False):
        """
        Trigger a live migration of the VM.

        :param host: The name of the host to migrate to.
        :param block_migration: Whether to use block migration.
        :param disk_over_commit: Whether to allow disk over commit.
        """
        # Live migration should keep SSH session active, so no need to indicate
        # to SSH that a reboot has occurred.
        self.vm.live_migrate(
            host=host,
            block_migration=block_migration,
            disk_over_commit=disk_over_commit,
        )

    def wait_for_state(self, desired_state, wait_time=1, retries=3, log_exception=True):
        """
        Checks a VM's state is what we're waiting for.  If not, wait a bit
        longer - up to a maximum number of times defined by retries

        :param desired_state: string describing the state we're waiting for
        :param retries: number of times to retry this check
        :param log_exception: whether or not failure to achieve desired state
         should result in an exception log.   Set to False if a more useful
         log is going to be made elsewhere to avoid spam.   (This is necessary
         because of the way this function is used in the non-object function
         wait_for_state)
        """
        _log.info("Waiting for VM %s to be in state %s", self.name, desired_state)

        def raise_unless_state():
            state = self.get_current_status()
            if state != desired_state:
                if state == "ERROR":
                    raise VmErrorState("VM is in state 'ERROR' and must be deleted.")
                else:
                    raise WrongState(
                        "Expected state: %s, got: %s." % (desired_state, state)
                    )

        retry_until_success(
            raise_unless_state,
            wait_time=wait_time,
            retries=retries,
            ex_class=WrongState,
            log_exception=log_exception,
            context_string="Vm.wait_for_state",
        )

    def get_all_addresses(self):
        """
        Uses the nova vm.interface objects to get a list of all IP addresses
        assigned to this VM. Doesn't use self.vm.addresses because this does
        not update to include added interfaces.

        :return: a list of all the IPs as netaddr objects.
        """
        try:
            interfaces = self.vm.interface_list()
        except Exception:
            if not self.tenant.controller.rebooting:
                _log.error("Controller is not rebooting but cannot query interfaces")
                raise
            _log.info("Using cached interface info during controller reboot")
            interfaces = self.cached_interfaces
        else:
            self.cached_interfaces = interfaces

        entries = itertools.chain(*[ifce.fixed_ips for ifce in interfaces])
        return [netaddr.IPAddress(entry["ip_address"]) for entry in entries]

    def get_ip_addr(self, version=4, network=None):
        """
        Returns the IP address of this VM (or None if there isn't one).

        :param version: - int - either 4 or 6 depending on what version you
        want.
        :return: IP address as a string in dotted decimal notation
        """
        ipvs = self.get_ip_addr_list(version=version, network=network)
        lng = len(ipvs)
        assert lng == 1, "VM interface has %s IPv%d addresses" % (lng, version)
        return ipvs[0]

    def get_ip_addr_list(self, version=4, network=None):
        if network:
            interface = self.vm.addresses[network]
        else:  # In most cases the VM will be attached to one network.
            interface = list(self.vm.addresses.values())[0]

        ips = [netaddr.IPAddress(entry["addr"]) for entry in interface]
        ipvs = [ip for ip in ips if ip.version == version]
        return ipvs

    def restarted(self):
        """
        Called to indicate that the VM has been restarted through some action
        such as a reboot of the host.  If so we remove the ssh connection as
        it may be out of date.  Any calls to use ssh connections (e.g. execute)
        should check and initiate ssh connections as required anyway
        """
        if self.ssh:
            self.ssh.disconnect()
            self.ssh = None

    def add_interface(self, net_name, sec_groups=None, fix_vm_routing=True):
        """
        Take a VM with one interface and turn it into a VM with two functioning
        interfaces.
        """
        self._add_interface_config()
        net_id = self.tenant.networks[net_name]
        body = {"network_id": net_id}
        if sec_groups:
            groups = self.tenant.security_groups
            sec_groups = [groups[group]["id"] for group in sec_groups]
            body.update({"security_groups": sec_groups})
        port = self.tenant.neutron.create_port({"port": body})
        self.vm.interface_attach(port_id=port["port"]["id"], net_id=None, fixed_ip=None)
        self.reboot()
        self.wait_for_state("ACTIVE", retries=300)

        if fix_vm_routing:
            # At this point we'll be able to connect to the VM on one of its
            # addresses, but not both.  This is because the VM will have 2
            # default routes - one for each interface, but in an unpredictable
            # order - of which the first one will always win for routing data
            # back to any IP outside the immediate subnets of the VM's two
            # interfaces (i.e., usually in this test suite, 10.28.0/24 and
            # 10.29.0/24).
            #
            # So, if we try to connect to 10.28.0.X, and the top default route
            # is via 10.28.0.X's interface, we get a successful connection.
            # But if we try to connect to 10.28.0.X, and the top default route
            # is via 10.29.0.X's interface, we don't get a connection, because
            # (a) the connection setup response has a source IP of 10.28.0.X,
            # but gets routed out of 10.29.0.X's interface; (b) when the
            # compute host does an RPF check on that response, it sees that the
            # interface used is not the right interface for traffic to
            # 10.28.0.X, and so drops the packet.
            #
            # We can set up source-based routing on the VM to avoid this
            # problem; we need rules and routes like these:
            #
            # sudo ip rule add from 10.28.0.X table 200
            # sudo ip route add default via 10.28.0.1 dev eth0 table 200
            # sudo ip rule add from 10.29.0.X table 201
            # sudo ip route add default via 10.29.0.1 dev eth1 table 201
            #
            # Then any outbound data from 10.28.0.X will go through 10.28.0.X's
            # interface, and similarly for 10.29.0.X.
            #
            # To set up those rules, we need to get into the VM, and we need to
            # try both possible addresses because we don't know which one will
            # work.
            all_ipv4 = [ip for ip in self.get_all_addresses() if ip.version == 4]
            for attempt in range(20):
                _log.info("Connection attempt %s", attempt)
                try:
                    self.restarted()
                    self.connect(interface=0)
                    break
                except Exception:
                    _log.exception("Failed to connect to first interface")
                try:
                    self.restarted()
                    self.connect(interface=1)
                    break
                except Exception:
                    _log.exception("Failed to connect to second interface")
                    if attempt == 10:
                        raise
                    time.sleep(5)
                    _log.info("Connected")

            # Now install source-based routing rules.  Sorting the addresses is how we
            # pair each interface name - eth0 or eth1 - with the right address -
            # 10.28... or 10.29...  That works because we assign from the 10.28 network
            # first, so 10.28... goes with eth0, but it would be more robust to match
            # interfaces and addresses directly.
            for ii, ipv4 in enumerate(sorted(all_ipv4)):
                self.execute(
                    "sudo ip rule add from %s table %s"
                    % (
                        str(ipv4),
                        200 + ii,
                    )
                )
                self.execute(
                    "sudo ip route add default via %s dev eth%s table %s"
                    % (
                        str(netaddr.IPNetwork(str(ipv4) + "/24")[1]),
                        ii,
                        200 + ii,
                    )
                )

            # Now check that we can connect to the VM on either of its
            # interfaces.
            self.restarted()
            self.connect(interface=0)
            self.restarted()
            self.connect(interface=1)

    def _add_interface_config(self):
        """Inject config for eth1 into a VM."""
        # Only tested on cirros
        assert self.image == CIRROS
        config = "\n" + "auto eth1\n" + "iface eth1 inet dhcp\n"
        cat = "sudo cat <<EOT >> /etc/network/interfaces\n%sEOT\n" % config
        command = "sudo sh -lc '%s'" % cat
        result = self.execute(command)
        if result.return_code:
            raise RuntimeError("Command failed: %s" % command)

    def change_advertised_ip(self, new_ip):
        """
        Changes the sender ip on packets going out, by adjusting the source ip
        in the postrouting table.
        :param new_ip: The ip address to use
        :return:
        """
        command = (
            "sudo iptables -t nat -A POSTROUTING -p icmp -j SNAT --to-source %s"
            % new_ip
        )
        self.execute(command)

    def speedup_sudo_on_ubuntu(self):
        """
        This allows us to use sudo without huge delays on Ubuntu machines
        :return:
        """
        self.execute("sudo bash -c 'echo 127.0.1.1 $(hostname) >> /etc/hosts'")

    def install_dpkg_from_test_rig(self, local_path):
        """
        Given a dpkg on the test rig, this copies it onto the vm and
        installs it
        :param local_path: The path of the dpkg on the machine the tests are
                           run from
        :return:
        """
        self.ssh.connect()
        self.ssh.send_file(local_path, "/tmp/dpkg_to_install.dpkg")
        self.execute("sudo dpkg -i /tmp/dpkg_to_install.dpkg")

    def set_up_tcpdump(self, output_file):
        """
        Set up tcpdump on the vm, recording all incoming packets to the given
        filename
        """
        # This is used by packet_received to know which file to read
        self.output_file = output_file
        # -A means we should get the payloads included in the file
        self.execute(
            "sudo tcpdump -AlU -i any icmp> {output_file} 2>&1 & disown".format(
                output_file=output_file
            )
        )
        # Wait for tcpdump to be ready to catch packets
        time.sleep(5)

    def packet_received(self, id_string):
        """
        Checks on this vm if a file contains details of a packet,
        searching for id_string which was in included in the packet payload.
        This method should be called after set_up_tcpdump, and will use
        self.output_file which was set up in that function
        """
        return_code = self.execute(
            "grep '{id_string}' {file}".format(
                file=self.output_file, id_string=id_string
            )
        ).return_code
        # 0 means that we found the string we looked for i.e. this packet's
        # id_string was found
        return return_code == 0

    def packet_ids_received(self, id_string):
        """
        Checks on this vm if a file contains details of a series of packets,
        all identified by the same id_string, succeeded by an identifier,
        i.e. searching on "my_id" would for packets "my_id01" and "my_id03"
        return ["01","03"]
        This method should be called after set_up_tcpdump, and will use
        self.output_file which was set up in that function
        """
        payloads = self.execute(
            "grep '{id_string}' {file}".format(
                file=self.output_file, id_string=id_string
            )
        ).stdout.split("\n")
        return [payload.partition(id_string)[2] for payload in payloads]


def wait_for_state(vms, desired_state, retries=3):
    """
    Waits for a set of VMs to reach a particular state.  This is faster than
    calling wait for state individually on each VM since the retries could
    stack up resulting in a slow fail condition.

    :param vms: Set of VMs.
    :param desired_state: string describing the state we're waiting for
    :param retries: number of times to retry this check
    """

    def check():
        for vm in vms:
            vm.wait_for_state(desired_state, retries=0, log_exception=False)

    retry_until_success(
        check, retries=retries, ex_class=WrongState, context_string="wait_for_state"
    )
