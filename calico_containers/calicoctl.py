#!/usr/bin/env python

# Copyright 2015 Metaswitch Networks
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

"""calicoctl

Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:4001]

Usage:
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>]
                           [--as=<AS_NUM>] [--log-dir=<LOG_DIR>]
  calicoctl node stop [--force]
  calicoctl node bgppeer add <PEER_IP> as <AS_NUM>
  calicoctl node bgppeer remove <PEER_IP>
  calicoctl node bgppeer show [--ipv4 | --ipv6]
  calicoctl status
  calicoctl profile show [--detailed]
  calicoctl profile (add|remove) <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule add (inbound|outbound) [--at=<POSITION>]
%(rule_spec)s
  calicoctl profile <PROFILE> rule remove (inbound|outbound) (--at=<POSITION>|
%(rule_spec)s)
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update
  calicoctl pool (add|remove) <CIDR> [--ipip] [--nat-outgoing]
  calicoctl pool show [--ipv4 | --ipv6]
  calicoctl default-node-as [<AS_NUM>]
  calicoctl bgppeer add <PEER_IP> as <AS_NUM>
  calicoctl bgppeer remove <PEER_IP>
  calicoctl bgppeer show [--ipv4 | --ipv6]
  calicoctl bgp-node-mesh [on|off]
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container <CONTAINER> endpoint-id show
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER> [--force]
  calicoctl endpoint show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>] [--endpoint=<ENDPOINT_ID>] [--detailed]
  calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]  [<PROFILES>...]
  calicoctl endpoint <ENDPOINT_ID> profile show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]
  calicoctl diags [--log-dir=<LOG_DIR>] [--upload]
  calicoctl checksystem [--fix]

Options:
 --interface=<INTERFACE>  The name to give to the interface in the container
                          [default: eth1]
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:libnetwork-release]
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.
 --log-dir=<LOG_DIR>      The directory for logs [default: /var/log/calico]
 --host=<HOSTNAME>        Filters endpoints on a specific host.
 --orchestrator=<ORCHESTRATOR_ID>    Filters endpoints created on a specific orchestrator.
 --workload=<WORKLOAD_ID> Filters endpoints on a specific workload.
 --endpoint=<ENDPOINT_ID> Filters endpoints with a specific endpoint ID.
 --as=<AS_NUM>            The AS number to assign to the node.
"""
__doc__ = __doc__ % {"rule_spec": """    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [<SRCCIDR>])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [<DSTCIDR>])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [<SRCCIDR>])]
           [(to   [(tag <DSTTAG>)] [<DSTCIDR>])] |
      [(from [(tag <SRCTAG>)] [<SRCCIDR>])]
      [(to   [(tag <DSTTAG>)] [<DSTCIDR>])]
    )]"""}
import json
import os
import re
import socket
from subprocess import CalledProcessError
import sys
import textwrap
import traceback

import netaddr
from docopt import docopt
import sh
import docker
import docker.utils
import docker.errors
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from prettytable import PrettyTable
from requests.exceptions import ConnectionError

from urllib3.exceptions import MaxRetryError

from pycalico import netns
from pycalico import diags
from pycalico.datastore import (ETCD_AUTHORITY_ENV,
                               ETCD_AUTHORITY_DEFAULT)
from calico_containers.pycalico.datastore_errors import DataStoreError, \
    ProfileNotInEndpoint, ProfileAlreadyInEndpoint, MultipleEndpointsMatch
from calico_containers.pycalico.datastore_datatypes import Rules, BGPPeer, IPPool, \
    Rule
from pycalico.ipam import IPAMClient

hostname = socket.gethostname()
client = IPAMClient()
DOCKER_VERSION = "1.16"
docker_client = docker.Client(version=DOCKER_VERSION,
                              base_url=os.getenv("DOCKER_HOST",
                                                 "unix://var/run/docker.sock"))

ORCHESTRATOR_ID = "docker"

try:
    sysctl = sh.Command._create("sysctl")
except sh.CommandNotFound as e:
    print "Missing command: %s" % e.message

DEFAULT_IPV4_POOL = IPPool("192.168.0.0/16")
DEFAULT_IPV6_POOL = IPPool("fd80:24e2:f998:72d6::/64")

class ConfigError(Exception):
    pass


class Vividict(dict):
    # From http://stackoverflow.com/a/19829714
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value


def get_container_info_or_exit(container_name):
    """
    Get the full container info array from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container info array, or sys.exit if not found.
    """
    try:
        info = docker_client.inspect_container(container_name)
    except docker.errors.APIError as e:
        if e.response.status_code == 404:
            print "Container %s was not found." % container_name
        else:
            print e.message
        sys.exit(1)
    return info


def get_container_id(container_name):
    """
    Get the full container ID from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container ID as a string.
    """
    info = get_container_info_or_exit(container_name)
    return info["Id"]


def enforce_root():
    """
    Check if the current process is running as the root user.
    :return: Nothing. sys.exit if not running as root.
    """
    if os.geteuid() != 0:
        print >> sys.stderr, "This command must be run as root."
        sys.exit(2)


def get_pool_or_exit(ip):
    """
    Get the first allocation pool that an IP is in.

    :param ip: The IPAddress to find the pool for.
    :return: The pool or sys.exit
    """
    pools = client.get_ip_pools("v%s" % ip.version)
    pool = None
    for candidate_pool in pools:
        if ip in candidate_pool:
            pool = candidate_pool
            break
    if pool is None:
        print "%s is not in any configured pools" % ip
        sys.exit(1)

    return pool


def container_add(container_name, ip, interface):
    """
    Add a container (on this host) to Calico networking with the given IP.

    :param container_name: The name or ID of the container.
    :param ip: An IPAddress object with the desired IP to assign.
    """
    # The netns manipulations must be done as root.
    enforce_root()
    info = get_container_info_or_exit(container_name)
    container_id = info["Id"]

    # Check if the container already exists
    try:
        _ = client.get_endpoint(hostname=hostname,
                                orchestrator_id=ORCHESTRATOR_ID,
                                workload_id=container_id)
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        # Calico already set up networking for this container.  Since we got
        # called with an IP address, we shouldn't just silently exit, since
        # that would confuse the user: the container would not be reachable on
        # that IP address.
        print "%s has already been configured with Calico Networking." % \
              container_name
        sys.exit(1)

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # Check the IP is in the allocation pool.  If it isn't, BIRD won't export
    # it.
    ip = IPAddress(ip)
    pool = get_pool_or_exit(ip)

    # The next hop IPs for this host are stored in etcd.
    next_hops = client.get_default_next_hops(hostname)
    try:
        next_hops[ip.version]
    except KeyError:
        print "This node is not configured for IPv%d." % ip.version
        sys.exit(1)

    # Assign the IP
    if not client.assign_address(pool, ip):
        print "IP address is already assigned in pool %s " % pool
        sys.exit(1)

    # Actually configure the netns. Defaults to eth1 since eth0 could
    # already be in use (e.g. by the Docker bridge)
    pid = info["State"]["Pid"]
    endpoint = netns.set_up_endpoint(ip=ip,
                                     hostname=hostname,
                                     orchestrator_id=ORCHESTRATOR_ID,
                                     workload_id=container_id,
                                     cpid=pid,
                                     next_hop_ips=next_hops,
                                     veth_name=interface,
                                     proc_alias="/proc")

    # Register the endpoint
    client.set_endpoint(endpoint)

    print "IP %s added to %s" % (ip, container_name)


def container_remove(container_name):
    """
    Remove a container (on this host) from Calico networking.

    The container may be left in a state without any working networking.
    If there is a network adaptor in the host namespace used by the container
    then it is removed.

    :param container_name: The name or ID of the container.
    """
    # The netns manipulations must be done as root.
    enforce_root()

    # Resolve the name to ID.
    workload_id = get_container_id(container_name)

    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=workload_id)
    except KeyError:
        print "Container %s doesn't contain any endpoints" % container_name
        sys.exit(1)

    # Remove any IP address assignments that this endpoint has
    for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
        assert(net.size == 1)
        ip = net.ip
        pools = client.get_ip_pools("v%s" % ip.version)
        for pool in pools:
            if ip in pool:
                # Ignore failure to unassign address, since we're not
                # enforcing assignments strictly in datastore.py.
                client.unassign_address(pool, ip)

    # Remove the endpoint
    netns.remove_endpoint(endpoint.endpoint_id)

    # Remove the container from the datastore.
    client.remove_workload(hostname, ORCHESTRATOR_ID, workload_id)

    print "Removed Calico interface from %s" % container_name


def node_stop(force):
    if force or len(client.get_endpoints(hostname=hostname, orchestrator_id=ORCHESTRATOR_ID)) == 0:
        client.remove_host(hostname)
        try:
            docker_client.stop("calico-node")
        except docker.errors.APIError as err:
            if err.response.status_code != 404:
                raise

        print "Node stopped and all configuration removed"
    else:
        print "Current host has active endpoints so can't be stopped." + \
              " Force with --force"


def module_loaded(module):
    return any(s.startswith(module) for s in open("/proc/modules").readlines())


def node(ip, node_image, log_dir, ip6="", as_num=None):
    """
    Create the calico-node container and establish Calico networking on this
    host.

    :param ip:  The IPv4 address of the host.
    :param node_image:  The calico-node image to use.
    :param ip6:  The IPv6 address of the host (or None if not configured)
    :param as_num:  The BGP AS Number to use for this node.  If not specified
    the global default value will be used.
    :return:  None.
    """
    # Ensure log directory exists
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)

    # Print warnings for any known system issues before continuing
    checksystem(fix=False, quit_if_error=False)

    # Set up etcd
    ipv4_pools = client.get_ip_pools("v4")
    ipv6_pools = client.get_ip_pools("v6")

    # Create default pools if required
    if not ipv4_pools:
        client.add_ip_pool("v4", DEFAULT_IPV4_POOL)
    if not ipv6_pools:
        client.add_ip_pool("v6", DEFAULT_IPV6_POOL)

    client.ensure_global_config()
    client.create_host(hostname, ip, ip6, as_num)

    try:
        docker_client.remove_container("calico-node", force=True)
    except docker.errors.APIError as err:
        if err.response.status_code != 404:
            raise

    etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)

    environment = [
        "HOSTNAME=%s" % hostname,
        "IP=%s" % ip,
        "IP6=%s" % (ip6 or ""),
        "ETCD_AUTHORITY=%s" % etcd_authority,  # etcd host:port
        "FELIX_ETCDADDR=%s" % etcd_authority,  # etcd host:port
    ]

    binds = {
        "/proc":
            {
                "bind": "/proc_host",
                "ro": False
            },
        log_dir:
            {
                "bind": "/var/log/calico",
                "ro": False
            },
        "/usr/share/docker/plugins/": #TODO make this an optional node
        # parameter like log_dir
        #"/run/docker/plugins/":
            {
                "bind": "/usr/share/docker/plugins",
                "ro": False
            }
    }

    host_config = docker.utils.create_host_config(
        privileged=True,
        restart_policy={"Name": "Always"},
        network_mode="host",
        binds=binds)

    _find_or_pull_node_image(node_image, docker_client)
    container = docker_client.create_container(
        node_image,
        name="calico-node",
        detach=True,
        environment=environment,
        host_config=host_config,
        volumes=["/proc_host",
                 "/var/log/calico",
                 "/usr/share/docker/plugins"])
    cid = container["Id"]

    docker_client.start(container)

    print "Calico node is running with id: %s" % cid


def normalize_version(version):
    """
    This function convers a string representation of a version into
    a list of integer values.
    e.g.:   "1.5.10" => [1, 5, 10]
    http://stackoverflow.com/questions/1714027/version-number-comparison
    """
    return [int(x) for x in re.sub(r'(\.0+)*$','', version).split(".")]

def checksystem(fix=False, quit_if_error=False):
    """
    Checks that the system is setup correctly. fix==True, this command will
    attempt to fix any issues it encounters. If any fixes fail, it will
    exit(1). Fix will automatically be set to True if the user specifies --fix
    at the command line.

    :param fix: if True, try to fix any system dependency issues that are
    detected.
    :param quit_if_error: if True, quit with error code 1 if any issues are
    detected, or if any fixes are unsuccesful.
    :return: True if all system dependencies are in the proper state, False if
    they are not. This function will sys.exit(1) instead of returning false if
    quit_if_error == True
    """
    # modprobe and sysctl require root privileges.
    enforce_root()

    system_ok = True
    modprobe = sh.Command._create('modprobe')
    ip6tables = sh.Command._create('ip6tables')
    try:
        ip6tables("-L")
    except:
        if fix:
            try:
                modprobe('ip6_tables')
            except sh.ErrorReturnCode:
                print >> sys.stderr, "ERROR: Could not enable ip6_tables."
                system_ok = False
        else:
            print >> sys.stderr, "WARNING: Unable to detect the ip6_tables " \
                                 "module. Load with `modprobe ip6_tables`"
            system_ok = False

    if not module_loaded("xt_set"):
        if fix:
            try:
                modprobe('xt_set')
            except sh.ErrorReturnCode:
                print >> sys.stderr, "ERROR: Could not enable xt_set."
                system_ok = False
        else:
            print >> sys.stderr, "WARNING: Unable to detect the xt_set " \
                                 "module. Load with `modprobe xt_set`"
            system_ok = False

    # Enable IP forwarding since all compute hosts are vRouters.
    # IPv4 forwarding should be enabled already by docker.
    if "1" not in sysctl("net.ipv4.ip_forward"):
        if fix:
            if "1" not in sysctl("-w", "net.ipv4.ip_forward=1"):
                print >> sys.stderr, "ERROR: Could not enable ipv4 forwarding."
                system_ok = False
        else:
            print >> sys.stderr, "WARNING: ipv4 forwarding is not enabled."
            system_ok = False

    if "1" not in sysctl("net.ipv6.conf.all.forwarding"):
        if fix:
            if "1" not in sysctl("-w", "net.ipv6.conf.all.forwarding=1"):
                print >> sys.stderr, "ERROR: Could not enable ipv6 forwarding."
                system_ok = False
        else:
            print >> sys.stderr, "WARNING: ipv6 forwarding is not enabled."
            system_ok = False

    # Check docker version compatability
    try:
        info = docker_client.version()
    except docker.errors.APIError:
        print >> sys.stderr, "ERROR: Docker server must support " \
                             "Docker Remote API v%s or greater." % DOCKER_VERSION
        system_ok = False
    else:
        api_version = normalize_version(info['ApiVersion'])
        # Check that API Version is above the minimum supported version
        if cmp(api_version, normalize_version(DOCKER_VERSION)) < 0:
            print >> sys.stderr, "ERROR: Docker server must support Docker " \
                                 "Remote API v%s or greater." % DOCKER_VERSION
            system_ok = False

    if quit_if_error and not system_ok:
        sys.exit(1)

    return system_ok


def _find_or_pull_node_image(image_name, client):
    """
    Check if Docker has a cached copy of an image, and if not, attempt to pull
    it.

    :param image_name: The full name of the image.
    :return: None.
    """
    try:
        _ = client.inspect_image(image_name)
    except docker.errors.APIError as err:
        if err.response.status_code == 404:
            # TODO: Display proper status bar
            print "Pulling Docker image %s" % image_name
            client.pull(image_name)


def grep(text, pattern):
    return "\n".join([line for line in text.splitlines() if pattern in line])


def status():
    calico_node_info = filter(lambda container: "/calico-node" in
                              container["Names"],
                              docker_client.containers())
    if len(calico_node_info) == 0:
        print "calico-node container not running"
    else:
        print "calico-node container is running. Status: %s" % \
              calico_node_info[0]["Status"]

        apt_cmd = docker_client.exec_create("calico-node", ["/bin/bash", "-c",
                                           "apt-cache policy calico-felix"])
        result = re.search(r"Installed: (.*?)\s", docker_client.exec_start(apt_cmd))
        if result is not None:
            print "Running felix version %s" % result.group(1)

        print "IPv4 Bird (BGP) status"
        bird_cmd = docker_client.exec_create("calico-node",
                                    ["/bin/bash", "-c",
                                     "echo show protocols | "
                                     "birdc -s /etc/service/bird/bird.ctl"])
        print docker_client.exec_start(bird_cmd)
        print "IPv6 Bird (BGP) status"
        bird6_cmd = docker_client.exec_create("calico-node",
                                    ["/bin/bash", "-c",
                                     "echo show protocols | "
                                     "birdc6 -s "
                                     "/etc/service/bird6/bird6.ctl"])
        print docker_client.exec_start(bird6_cmd)


def profile_add(profile_name):
    """
    Create a policy profile with the given name.
    :param profile_name: The name for the profile.
    :return: None.
    """
    # Check if the profile exists.
    if client.profile_exists(profile_name):
        print "Profile %s already exists." % profile_name
    else:
        # Create the profile.
        client.create_profile(profile_name)
        print "Created profile %s" % profile_name


def profile_remove(profile_name):
    # TODO - Don't allow removing a profile that has endpoints in it.
    try:
        client.remove_profile(profile_name)
    except KeyError:
        print "Couldn't find profile with name %s" % profile_name
    else:
        print "Deleted profile %s" % profile_name


def profile_show(detailed):
    profiles = client.get_profile_names()

    if detailed:
        x = PrettyTable(["Name", "Host", "Orchestrator ID", "Workload ID",
                         "Endpoint ID", "State"])
        for name in profiles:
            members = client.get_profile_members(name)
            if not members:
                x.add_row([name, "None", "None", "None", "None", "None"])
                continue

            for endpoint in members:
                x.add_row([name,
                           endpoint.hostname,
                           endpoint.orchestrator_id,
                           endpoint.workload_id,
                           endpoint.endpoint_id,
                           endpoint.state])
    else:
        x = PrettyTable(["Name"])
        for name in profiles:
            x.add_row([name])

    print x.get_string(sortby="Name")


def profile_tag_show(name):
    """Show the tags on the profile."""
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    for tag in profile.tags:
        print tag


def profile_tag_add(name, tag):
    """
    Add a tag to the profile.
    :param name: Profile name
    :param tag: Tag name
    :return: None
    """
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    profile.tags.add(tag)
    client.profile_update_tags(profile)
    print "Tag %s added to profile %s" % (tag, name)


def profile_tag_remove(name, tag):
    """
    Remove a tag from the profile.
    :param name: Profile name
    :param tag: Tag name
    :return: None
    """
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    try:
        profile.tags.remove(tag)
    except KeyError:
        print "Tag %s is not on profile %s" % (tag, name)
        sys.exit(1)
    client.profile_update_tags(profile)
    print "Tag %s removed from profile %s" % (tag, name)


def profile_rule_show(name, human_readable=False):
    """Show the rules on the profile."""
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if human_readable:
        print "Inbound rules:"
        for i, rule in enumerate(profile.rules.inbound_rules, start=1):
            print " %3d %s" % (i, rule.pprint())
        print "Outbound rules:"
        for i, rule in enumerate(profile.rules.outbound_rules, start=1):
            print " %3d %s" % (i, rule.pprint())
    else:
        json.dump(profile.rules._asdict(),
                  sys.stdout,
                  indent=2)
        print ""


def profile_rule_update(name):
    """Update the rules on the profile"""
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    # Read in the JSON from standard in.
    rules_str = sys.stdin.read()
    rules = Rules.from_json(rules_str)
    if rules.id != name:
        print 'Rules JSON "id"=%s doesn\'t match profile name %s.' % \
              (rules.id, name)
        sys.exit(1)

    profile.rules = rules
    client.profile_update_rules(profile)
    print "Successfully updated rules on profile %s" % name


def profile_rule_add_remove(
        operation,
        name, position, action, direction,
        protocol=None,
        icmp_type=None, icmp_code=None,
        src_net=None, src_tag=None, src_ports=None,
        dst_net=None, dst_tag=None, dst_ports=None):
    """
    Add or remove a rule from a profile.

    Arguments not documented below are passed through to the rule.

    :param operation: "add" or "remove".
    :param name: Name of the profile.
    :param position: Position to insert/remove rule or None for the default.
    :param action: Rule action: "allow" or "deny".
    :param direction: "inbound" or "outbound".

    :return:
    """
    if icmp_type is not None:
        try:
            icmp_type = int(icmp_type)
        except ValueError:
            print "ICMP type should be an integer"
            sys.exit(1)
        if not (0 <= icmp_type < 255):  # Felix doesn't support 255.
            print "ICMP type out of range"
            sys.exit(1)
    if icmp_code is not None:
        try:
            icmp_code = int(icmp_code)
        except ValueError:
            print "ICMP code should be an integer"
            sys.exit(1)
        if not (0 <= icmp_code < 255):  # Felix doesn't support 255.
            print "ICMP code out of range"
            sys.exit(1)

    # Convert the input into a Rule.
    rule_dict = {k: v for (k, v) in locals().iteritems()
                 if k in Rule.ALLOWED_KEYS and v is not None}
    rule_dict["action"] = action
    if (protocol not in ("tcp", "udp")) and (src_ports is not None or
                                             dst_ports is not None):
        print "Ports are not valid with protocol %r" % protocol
        sys.exit(1)
    rule = Rule(**rule_dict)

    # Get the profile.
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if direction == "inbound":
        rules = profile.rules.inbound_rules
    else:
        rules = profile.rules.outbound_rules

    if operation == "add":
        if position is None:
            # Default to append.
            position = len(rules) + 1
        if not 0 < position <= len(rules) + 1:
            print "Position %s is out-of-range." % position
        if rule in rules:
            print "Rule already present, skipping."
            return
        rules.insert(position - 1, rule)  # Accepts 0 and len(rules).
    else:
        # Remove.
        if position is not None:
            # Position can only be used on its own so no need to examine the
            # rule.
            if 0 < position <= len(rules):  # 1-indexed
                rules.pop(position - 1)
            else:
                print "Rule position out-of-range."
        else:
            # Attempt to match the rule.
            try:
                rules.remove(rule)
            except ValueError:
                print "Rule not found."
                sys.exit(1)
    client.profile_update_rules(profile)


def save_diags(log_dir, upload):
    """
    Gather Calico diagnostics for bug reporting.
    :return: None
    """
    # This needs to be run as root.
    enforce_root()
    print("Collecting diags")
    diags.save_diags(log_dir, upload)

def ip_pool_add(cidr_pool, version, ipip, masquerade):
    """
    Add the the given CIDR range to the IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :param version: v4 or v6
    :param ipip: Use IP in IP for this pool.
    :return: None
    """
    if version == "v6" and ipip:
        print "IP in IP not supported for IPv6 pools"
        sys.exit(1)

    cidr = check_ip_version(cidr_pool, version, IPNetwork)
    pool = IPPool(cidr, ipip=ipip, masquerade=masquerade)
    client.add_ip_pool(version, pool)


def ip_pool_remove(cidr_pool, version):
    """
    Add the the given CIDR range to the IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :param version: v4 or v6
    :return: None
    """
    cidr = check_ip_version(cidr_pool, version, IPNetwork)
    try:
        client.remove_ip_pool(version, cidr)
    except KeyError:
        print "%s is not a configured pool." % cidr_pool


def ip_pool_show(version):
    """
    Print a list of IP allocation pools.
    :return: None
    """
    assert version in ("v4", "v6")
    headings = ["IP%s CIDR" % version, "Options"]
    pools = client.get_ip_pools(version)
    x = PrettyTable(headings)
    for pool in pools:
        enabled_options = []
        if version == "v4":
            if pool.ipip:
                enabled_options.append("ipip")
            if pool.masquerade:
                enabled_options.append("nat-outgoing")
        # convert option array to string
        row = [str(pool.cidr), ','.join(enabled_options)]
        x.add_row(row)
    print x.get_string(sortby=headings[0])

def set_bgp_node_mesh(enable):
    """
    Set the BGP node mesh setting.

    :param enable:  (Boolean) Whether to enable or disable the node-to-node
    mesh.
    :return: None.
    """
    client.set_bgp_node_mesh(enable)


def show_bgp_node_mesh():
    """
    Display the BGP node mesh setting.

    :return: None.
    """
    value = client.get_bgp_node_mesh()
    print "on" if value else "off"


def set_default_node_as(as_num):
    """
    Set the default node BGP AS Number.

    :param as_num:  The default AS number
    :return: None.
    """
    client.set_default_node_as(as_num)


def show_default_node_as():
    """
    Display the default node BGP AS Number.

    :return: None.
    """
    value = client.get_default_node_as()
    print value


def bgppeer_add(ip, version, as_num):
    """
    Add a new global BGP peer with the supplied IP address and AS Number.  All
    nodes will peer with this.

    :param ip: The address to add
    :param version: v4 or v6
    :param as_num: The peer AS Number.
    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)
    peer = BGPPeer(address, as_num)
    client.add_bgp_peer(version, peer)


def bgppeer_remove(ip, version):
    """
    Remove a global BGP peer.

    :param ip: The address to use.
    :param version: v4 or v6
    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)
    try:
        client.remove_bgp_peer(version, address)
    except KeyError:
        print "%s is not a globally configured peer." % address
        sys.exit(1)
    else:
        print "BGP peer removed from global configuration"

def bgppeer_show(version):
    """
    Print a list of the global BGP Peers.
    """
    assert version in ("v4", "v6")
    peers = client.get_bgp_peers(version)
    if peers:
        heading = "Global IP%s BGP Peer" % version
        x = PrettyTable([heading, "AS Num"], sortby=heading)
        for peer in peers:
            x.add_row([peer.ip, peer.as_num])
        x.align = "l"
        print x.get_string(sortby=heading)
    else:
        print "No global IP%s BGP Peers defined.\n" % version


def node_bgppeer_add(ip, version, as_num):
    """
    Add a new BGP peer with the supplied IP address and AS Number to this node.

    :param ip: The address to add
    :param version: v4 or v6
    :param as_num: The peer AS Number.
    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)
    peer = BGPPeer(address, as_num)
    client.add_bgp_peer(version, peer, hostname=hostname)


def node_bgppeer_remove(ip, version):
    """
    Remove a global BGP peer from this node.

    :param ip: The address to use.
    :param version: v4 or v6
    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)
    try:
        client.remove_bgp_peer(version, address, hostname=hostname)
    except KeyError:
        print "%s is not a configured peer for this node." % address
        sys.exit(1)
    else:
        print "BGP peer removed from node configuration"


def node_bgppeer_show(version):
    """
    Print a list of the BGP Peers for this node.
    """
    assert version in ("v4", "v6")
    peers = client.get_bgp_peers(version, hostname=hostname)
    if peers:
        heading = "Node specific IP%s BGP Peer" % version
        x = PrettyTable([heading, "AS Num"], sortby=heading)
        for peer in peers:
            x.add_row([peer.ip, peer.as_num])
        x.align = "l"
        print x.get_string(sortby=heading)
    else:
        print "No IP%s BGP Peers defined for this node.\n" % version


def check_ip_version(ip, version, cls):
    """
    Parses and checks that the given IP matches the provided version.
    :param ip: The IP (string) to check.
    :param version: The version
    :param cls: The type of IP object (IPAddress or IPNetwork)
    :return: The parsed object of type "type"
    """
    assert version in ("v4", "v6")
    try:
        parsed = cls(ip)
    except AddrFormatError:
        print "%s is not a valid IP address." % ip
        sys.exit(1)
    if "v%d" % parsed.version != version:
        print "%s is an IPv%d prefix, this command is for IP%s." % \
              (parsed, parsed.version, version)
        sys.exit(1)
    return parsed

def container_endpoint_id_show(container_name):
    workload_id = get_container_id(container_name)
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=workload_id)
        print endpoint.endpoint_id
    except KeyError:
        print "No endpoint was found for %s" % container_name

def container_ip_add(container_name, ip, version, interface):
    """
    Add an IP address to an existing Calico networked container.

    :param container_name: The name of the container.
    :param ip: The IP to add
    :param version: The IP version ("v4" or "v6")
    :param interface: The name of the interface in the container.

    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)

    # The netns manipulations must be done as root.
    enforce_root()

    pool = get_pool_or_exit(address)

    info = get_container_info_or_exit(container_name)
    container_id = info["Id"]

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # Check that the container is already networked
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=container_id)
    except KeyError:
        print "Failed to add IP address to container.\n"
        print_container_not_in_calico_msg(container_name)
        sys.exit(1)

    # From here, this method starts having side effects. If something
    # fails then at least try to leave the system in a clean state.
    if not client.assign_address(pool, ip):
        print "IP address is already assigned in pool %s " % pool
        sys.exit(1)

    try:
        if address.version == 4:
            endpoint.ipv4_nets.add(IPNetwork(address))
        else:
            endpoint.ipv6_nets.add(IPNetwork(address))
        client.update_endpoint(endpoint)
    except (KeyError, ValueError):
        client.unassign_address(pool, ip)
        print "Error updating datastore. Aborting."
        sys.exit(1)

    try:
        container_pid = info["State"]["Pid"]
        netns.add_ip_to_interface(container_pid,
                                  address,
                                  interface,
                                  proc_alias="/proc")
    except CalledProcessError:
        print "Error updating networking in container. Aborting."
        if address.version == 4:
            endpoint.ipv4_nets.remove(IPNetwork(address))
        else:
            endpoint.ipv6_nets.remove(IPNetwork(address))
        client.update_endpoint(endpoint)
        client.unassign_address(pool, ip)
        sys.exit(1)

    print "IP %s added to %s" % (ip, container_id)


def container_ip_remove(container_name, ip, version, interface):
    """
    Add an IP address to an existing Calico networked container.

    :param container_name: The name of the container.
    :param ip: The IP to add
    :param version: The IP version ("v4" or "v6")
    :param interface: The name of the interface in the container.

    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)

    # The netns manipulations must be done as root.
    enforce_root()

    pool = get_pool_or_exit(address)

    info = get_container_info_or_exit(container_name)
    container_id = info["Id"]

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # Check that the container is already networked
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=ORCHESTRATOR_ID,
                                       workload_id=container_id)
        if address.version == 4:
            nets = endpoint.ipv4_nets
        else:
            nets = endpoint.ipv6_nets

        if not IPNetwork(address) in nets:
            print "IP address is not assigned to container. Aborting."
            sys.exit(1)

    except KeyError:
        print "Container is unknown to Calico."
        sys.exit(1)

    try:
        nets.remove(IPNetwork(address))
        client.update_endpoint(endpoint)
    except (KeyError, ValueError):
        print "Error updating datastore. Aborting."
        sys.exit(1)

    try:
        container_pid = info["State"]["Pid"]
        netns.remove_ip_from_interface(container_pid,
                                       address,
                                       interface,
                                       proc_alias="/proc")

    except CalledProcessError:
        print "Error updating networking in container. Aborting."
        sys.exit(1)

    client.unassign_address(pool, ip)

    print "IP %s removed from %s" % (ip, container_name)


def endpoint_show(hostname, orchestrator_id, workload_id, endpoint_id,
                  detailed):
    """
    List the profiles for a given endpoint. All parameters will be used to
    filter down which endpoints should be shown.

    :param endpoint_id: The endpoint ID.
    :param workload_id: The workload ID.
    :param orchestrator_id: The orchestrator ID.
    :param hostname: The hostname.
    :param detailed: Optional flag, when set to True, will provide more
    information in the shown table
    :return: Nothing
    """
    endpoints = client.get_endpoints(hostname=hostname,
                                     orchestrator_id=orchestrator_id,
                                     workload_id=workload_id,
                                     endpoint_id=endpoint_id)

    if detailed:
        headings = ["Hostname",
                    "Orchestrator ID",
                    "Workload ID",
                    "Endpoint ID",
                    "Addresses",
                    "MAC",
                    "Profiles",
                    "State"]
        x = PrettyTable(headings, sortby="Hostname")

        for endpoint in endpoints:
            x.add_row([endpoint.hostname,
                       endpoint.orchestrator_id,
                       endpoint.workload_id,
                       endpoint.endpoint_id,
                       "\n".join([str(net) for net in endpoint.ipv4_nets | endpoint.ipv6_nets]),
                       endpoint.mac,
                       ','.join(endpoint.profile_ids),
                       endpoint.state])
    else:
        headings = ["Hostname",
                    "Orchestrator ID",
                    "NumWorkloads",
                    "NumEndpoints"]
        x = PrettyTable(headings, sortby="Hostname")

        """ To calculate the number of unique endpoints, and unique workloads
         on each host, we first create a dictionary in the following format:
        {
        host1: {
            workload1: num_workload1_endpoints,
            workload2: num_workload2_endpoints,
            ...
            },
        host2: {
            workload3: num_workload3_endpoints,
            workload4: num_workload4_endpoints,
            ...
        }
        """
        # Use a vividict so the host key is automatically set
        table_dict = Vividict()
        for endpoint in endpoints:
            if endpoint.workload_id not in table_dict[endpoint.hostname]:
                table_dict[endpoint.hostname][endpoint.workload_id] = 0
            table_dict[endpoint.hostname][endpoint.workload_id] += 1

        # This table has one entry for each host. So loop through the hosts
        for host in table_dict:
            # Check how many workloads belong to each host
            num_workloads = len(table_dict[host])

            # Add up how many endpoints each workload on this host has
            num_endpoints = 0
            for workload, endpoints in iter(table_dict[host].items()):
                num_endpoints += endpoints

            # Add the results to this table
            new_row = [endpoint.hostname,
                       endpoint.orchestrator_id,
                       num_workloads,
                       num_endpoints]

            x.add_row(new_row)
    print str(x) + "\n"


def endpoint_profile_append(hostname, orchestrator_id, workload_id,
                            endpoint_id, profile_names):
    """
    Append a list of profiles to the container endpoint profile list.

    The hostname, orchestrator_id, workload_id, and endpoint_id are all
    optional parameters used to determine which endpoint is being targeted.
    The more parameters used, the faster the endpoint query will be. The
    query must be specific enough to match a single endpoint or it will fail.

    The profile list may not contain duplicate entries, invalid profile names,
    or profiles that are already in the containers list.

    :param hostname: The host that the targeted endpoint resides on.
    :param orchestrator_id: The orchestrator that created the targeted endpoint.
    :param workload_id: The ID of workload which created the targeted endpoint.
    :param endpoint_id: The endpoint ID of the targeted endpoint.
    :param profile_names: The list of profile names to add to the targeted
                        endpoint.
    :return: None
    """
    # Validate the profile list.
    validate_profile_list(profile_names)
    try:
        client.append_profiles_to_endpoint(profile_names,
                                           hostname=hostname,
                                           orchestrator_id=orchestrator_id,
                                           workload_id=workload_id,
                                           endpoint_id=endpoint_id)
        print_paragraph("Profiles %s appended to %s." %
                          (", ".join(profile_names), endpoint_id))
    except KeyError:
        print "Failed to append profiles to endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)
    except ProfileAlreadyInEndpoint, e:
        print_paragraph("Profile %s is already in endpoint "
                        "profile list" % e.profile_name)
    except MultipleEndpointsMatch:
        print_paragraph("More than 1 endpoint matches the provided criteria.  "
                        "Please provide additional parameters to refine the "
                        "search.")
        sys.exit(1)


def endpoint_profile_set(hostname, orchestrator_id, workload_id,
                         endpoint_id, profile_names):
    """
    Set the complete list of profiles for the container endpoint profile list.

    The hostname, orchestrator_id, workload_id, and endpoint_id are all optional
    parameters used to determine which endpoint is being targeted.
    The more parameters used, the faster the endpoint query will be. The
    query must be specific enough to match a single endpoint or it will fail.

    The profile list may not contain duplicate entries or invalid profile names.

    :param hostname: The host that the targeted endpoint resides on.
    :param orchestrator_id: The orchestrator that created the targeted endpoint.
    :param workload_id: The ID of workload which created the targeted endpoint.
    :param endpoint_id: The endpoint ID of the targeted endpoint.
    :param profile_names: The list of profile names to set on the targeted endpoint.

    :return: None
    """
    # Validate the profile list.
    validate_profile_list(profile_names)

    try:
        client.set_profiles_on_endpoint(profile_names,
                                        hostname=hostname,
                                        orchestrator_id=orchestrator_id,
                                        workload_id=workload_id,
                                        endpoint_id=endpoint_id)
        print_paragraph("Profiles %s set for %s." %
                          (", ".join(profile_names), endpoint_id))
    except KeyError:
        print "Failed to set profiles for endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)


def endpoint_profile_remove(hostname, orchestrator_id, workload_id,
                            endpoint_id, profile_names):
    """
    Remove a list of profiles from the endpoint profile list.

    The hostname, orchestrator_id, workload_id, and endpoint_id are all optional
    parameters used to determine which endpoint is being targeted.
    The more parameters used, the faster the endpoint query will be. The
    query must be specific enough to match a single endpoint or it will fail.

    The profile list may not contain duplicate entries, invalid profile names,
    or profiles that are not already in the containers list.

    :param hostname: The host that the targeted endpoint resides on.
    :param orchestrator_id: The orchestrator that created the targeted endpoint.
    :param workload_id: The ID of workload which created the targeted endpoint.
    :param endpoint_id: The endpoint ID of the targeted endpoint.
    :param profile_names: The list of profile names to remove from the targeted
                          endpoint.
    :return: None
    """
    # Validate the profile list.
    validate_profile_list(profile_names)

    try:
        client.remove_profiles_from_endpoint(profile_names,
                                             hostname=hostname,
                                             orchestrator_id=orchestrator_id,
                                             workload_id=workload_id,
                                             endpoint_id=endpoint_id)
        print_paragraph("Profiles %s removed from %s." %
                          (",".join(profile_names), endpoint_id))
    except KeyError:
        print "Failed to remove profiles from endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)
    except ProfileNotInEndpoint, e:
        print_paragraph("Profile %s is not in endpoint profile " \
                        "list." % e.profile_name)
    except MultipleEndpointsMatch:
        print "More than 1 endpoint matches the provided criteria. " \
              "Please provide additional parameters to refine the search."
        sys.exit(1)


def endpoint_profile_show(hostname, orchestrator_id, workload_id, endpoint_id):
    """
    List the profiles assigned to a particular endpoint.

    :param hostname: The hostname.
    :param orchestrator_id: The orchestrator ID.
    :param workload_id: The workload ID.
    :param endpoint_id: The endpoint ID.

    :return: None
    """
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                        orchestrator_id=orchestrator_id,
                                        workload_id=workload_id,
                                        endpoint_id=endpoint_id)
    except MultipleEndpointsMatch:
        print "Failed to list profiles in endpoint.\n"
        print_paragraph("More than 1 endpoint matches the provided "
                        "criteria.  Please provide additional parameters to "
                        "refine the search.")
        sys.exit(1)
    except KeyError:
        print "Failed to list profiles in endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)

    if endpoint.profile_ids:
        x = PrettyTable(["Name"], sortby="Name")
        for name in endpoint.profile_ids:
            x.add_row([name])
        print str(x) + "\n"
    else:
        print "Endpoint has no profiles associated with it."


def validate_profile_list(profile_names):
    """
    Validate a list of profiles.  This checks that each profile name is
    valid and specified only once in the list.

    This method traces and exits upon failure.

    :param profile_names: The list of profiles to check.
    :return: None
    """
    compiled = set()
    for profile_name in profile_names:
        if not client.profile_exists(profile_name):
            print "Profile with name %s was not found." % profile_name
            sys.exit(1)
        if profile_name in compiled:
            print "Profile with name %s was specified more than " \
                  "once." % profile_name
            sys.exit(1)
        compiled.add(profile_name)


def validate_arguments():
    """
    Validate common argument values.
    """
    # List of valid characters that Felix permits
    valid_chars = '[a-zA-Z0-9_\.\-]'
    profile_ok = True
    if arguments["<PROFILES>"] or arguments["<PROFILE>"]:
        profiles = arguments["<PROFILES>"] or [arguments["<PROFILE>"]]
        for profile in profiles:
            if not re.match("^%s{1,40}$" % valid_chars, profile):
                profile_ok = False
                break

    tag_ok = (arguments["<TAG>"] is None or
              re.match("^%s+$" % valid_chars, arguments["<TAG>"]))
    ip_ok = arguments["--ip"] is None or netaddr.valid_ipv4(arguments["--ip"])
    ip6_ok = arguments["--ip6"] is None or \
             netaddr.valid_ipv6(arguments["--ip6"])
    container_ip_ok = arguments["<IP>"] is None or \
                      netaddr.valid_ipv4(arguments["<IP>"]) or \
                      netaddr.valid_ipv6(arguments["<IP>"])
    peer_ip_ok = arguments["<PEER_IP>"] is None or \
                 netaddr.valid_ipv4(arguments["<PEER_IP>"]) or \
                 netaddr.valid_ipv6(arguments["<PEER_IP>"])
    cidr_ok = True
    for arg in ["<CIDR>", "<SRCCIDR>", "<DSTCIDR>"]:
        if arguments[arg]:
            try:
                arguments[arg] = str(IPNetwork(arguments[arg]))
            except (AddrFormatError, ValueError):
                # Some versions of Netaddr have a bug causing them to return a
                # ValueError rather than an AddrFormatError, so catch both.
                cidr_ok = False
    icmp_ok = True
    for arg in ["<ICMPCODE>", "<ICMPTYPE>"]:
        if arguments[arg] is not None:
            try:
                value = int(arguments[arg])
                if not (0 <= value < 255):  # Felix doesn't support 255
                    raise ValueError("Invalid %s: %s" % (arg, value))
            except ValueError:
                icmp_ok = False
    asnum_ok = True
    if arguments["<AS_NUM>"] or arguments["--as"]:
        try:
            asnum = int(arguments["<AS_NUM>"] or arguments["--as"])
            asnum_ok = 0 <= asnum <= 4294967295
        except ValueError:
            asnum_ok = False

    if not profile_ok:
        print_paragraph("Profile names must be < 40 character long and can "
                        "only contain numbers, letters, dots, dashes and "
                        "underscores.")
    if not tag_ok:
        print_paragraph("Tags names can only contain numbers, letters, dots, "
                        "dashes and underscores.")
    if not ip_ok:
        print "Invalid IPv4 address specified with --ip argument."
    if not ip6_ok:
        print "Invalid IPv6 address specified with --ip6 argument."
    if not container_ip_ok or not peer_ip_ok:
        print "Invalid IP address specified."
    if not cidr_ok:
        print "Invalid CIDR specified."
    if not icmp_ok:
        print "Invalid ICMP type or code specified."
    if not asnum_ok:
        print "Invalid AS Number specified."

    if not (profile_ok and ip_ok and ip6_ok and tag_ok and peer_ip_ok and
                container_ip_ok and cidr_ok and icmp_ok and asnum_ok):
        sys.exit(1)


def get_container_ipv_from_arguments():
    """
    Determine the container IP version from the arguments.
    :return: The IP version.  One of "v4", "v6" or None.
    """
    version = None
    if arguments["--ipv4"]:
        version = "v4"
    elif arguments["--ipv6"]:
        version = "v6"
    elif arguments["<IP>"]:
        version = "v%s" % IPAddress(arguments["<IP>"]).version
    elif arguments["<PEER_IP>"]:
        version = "v%s" % IPAddress(arguments["<PEER_IP>"]).version
    elif arguments["<CIDR>"]:
        version = "v%s" % IPNetwork(arguments["<CIDR>"]).version
    return version


def permission_denied_error(conn_error):
    """
    Determine whether the supplied connection error is from a permission denied
    error.
    :param conn_error: A requests.exceptions.ConnectionError instance
    :return: True if error is from permission denied.
    """
    # Grab the MaxRetryError from the ConnectionError arguments.
    mre = None
    for arg in conn_error.args:
        if isinstance(arg, MaxRetryError):
            mre = arg
            break
    if not mre:
        return None

    # See if permission denied is in the MaxRetryError arguments.
    se = None
    for arg in mre.args:
        if "Permission denied" in str(arg):
            se = arg
            break
    if not se:
        return None

    return True


def print_container_not_in_calico_msg(container_name):
    """
    Display message indicating that the supplied container is not known to
    Calico.
    :param container_name: The container name.
    :return: None.
    """
    print_paragraph("Container %s is unknown to Calico." % container_name)
    print_paragraph("Use `calicoctl container add` to add the container "
                    "to the Calico network.")


def print_paragraph(msg):
    """
    Print a fixed width (80 chars) paragraph of text.
    :param msg: The msg to print.
    :return: None.
    """
    print "\n".join(textwrap.wrap(msg, width=80))
    print


def parse_ports(ports_str):
    """
    Parse a string representing a port list into a list of ports and
    port ranges.

    Returns None if the input is None.

    :param StringTypes|NoneType ports_str: string representing a port list.
        Examples: "1" "1,2,3" "1:3" "1,2,3:4"
    :return list[StringTypes|int]|NoneType: list of ports or None.
    """
    if ports_str is None:
        return None
    # We allow ranges with : or - but convert to :, which is what the data
    # model uses.
    if not re.match(r'^(\d+([:-]\d+)?)(,\d+([:-]\d+)?)*$',
                    ports_str):
        print_paragraph("Ports: %r are invalid; expecting a comma-separated "
                        "list of ports and port ranges." % ports_str)
        sys.exit(1)
    splits = ports_str.split(",")
    parsed_ports = []
    for split in splits:
        m = re.match(r'^(\d+)[:-](\d+)$', split)
        if m:
            # Got a range, canonicalise it.
            min = int(m.group(1))
            max = int(m.group(2))
            if min > max:
                print "Port range minimum (%s) > maximum (%s)." % (min, max)
                sys.exit(1)
            if not (0 <= min <= 65535):
                print "Port minimum (%s) out-of-range." % min
                sys.exit(1)
            if not (0 <= max <= 65535):
                print "Port maximum (%s) out-of-range." % max
                sys.exit(1)
            parsed_ports.append("%s:%s" % (min, max))
        else:
            # Should be a lone port, convert to int.
            port = int(split)
            if not (0 <= port <= 65535):
                print "Port (%s) out-of-range." % min
                sys.exit(1)
            parsed_ports.append(port)
    return parsed_ports


if __name__ == '__main__':
    arguments = docopt(__doc__)
    validate_arguments()
    ip_version = get_container_ipv_from_arguments()
    try:
        if arguments["node"]:
            if arguments["bgppeer"]:
                if arguments["add"]:
                    node_bgppeer_add(arguments["<PEER_IP>"], ip_version,
                                     arguments["<AS_NUM>"])
                elif arguments["remove"]:
                    node_bgppeer_remove(arguments["<PEER_IP>"], ip_version)
                elif arguments["show"]:
                    if not ip_version:
                        node_bgppeer_show("v4")
                        node_bgppeer_show("v6")
                    else:
                        node_bgppeer_show(ip_version)
            elif arguments["stop"]:
                node_stop(arguments["--force"])
            else:
                node(arguments["--ip"],
                     node_image=arguments['--node-image'],
                     log_dir=arguments["--log-dir"],
                     ip6=arguments["--ip6"],
                     as_num=arguments["--as"])
        elif arguments["status"]:
            status()
        elif arguments["checksystem"]:
            checksystem(arguments["--fix"], quit_if_error=True)
        elif arguments["endpoint"]:
            if arguments["profile"]:
                if arguments["append"]:
                    endpoint_profile_append(arguments["--host"],
                                            arguments["--orchestrator"],
                                            arguments["--workload"],
                                            arguments["<ENDPOINT_ID>"],
                                            arguments['<PROFILES>'])
                elif arguments["remove"]:
                    endpoint_profile_remove(arguments["--host"],
                                            arguments["--orchestrator"],
                                            arguments["--workload"],
                                            arguments["<ENDPOINT_ID>"],
                                            arguments['<PROFILES>'])
                elif arguments["set"]:
                    endpoint_profile_set(arguments["--host"],
                                         arguments["--orchestrator"],
                                         arguments["--workload"],
                                         arguments["<ENDPOINT_ID>"],
                                         arguments['<PROFILES>'])
                elif arguments["show"]:
                    endpoint_profile_show(arguments["--host"],
                                          arguments["--orchestrator"],
                                          arguments["--workload"],
                                          arguments["<ENDPOINT_ID>"])
            else:
                # calicoctl endpoint show
                endpoint_show(arguments["--host"],
                              arguments["--orchestrator"],
                              arguments["--workload"],
                              arguments["--endpoint"],
                              arguments["--detailed"])
        elif arguments["profile"]:
            if arguments["tag"] and not arguments["rule"]:
                if arguments["show"]:
                    profile_tag_show(arguments["<PROFILE>"])
                elif arguments["add"]:
                    profile_tag_add(arguments["<PROFILE>"],
                                    arguments["<TAG>"])
                elif arguments["remove"]:
                    profile_tag_remove(arguments["<PROFILE>"],
                                       arguments["<TAG>"])
            elif arguments["rule"]:
                if arguments["show"]:
                    profile_rule_show(arguments["<PROFILE>"],
                                      human_readable=True)
                elif arguments["json"]:
                    profile_rule_show(arguments["<PROFILE>"],
                                      human_readable=False)
                elif arguments["update"]:
                    profile_rule_update(arguments["<PROFILE>"])
                elif arguments["add"] or arguments["remove"]:
                    operation = "add" if arguments["add"] else "remove"
                    action = "allow" if arguments.get("allow") else "deny"
                    direction = ("inbound" if arguments["inbound"]
                                 else "outbound")
                    if arguments["tcp"]:
                        protocol = "tcp"
                    elif arguments["udp"]:
                        protocol = "udp"
                    elif arguments["icmp"]:
                        protocol = "icmp"
                    else:
                        protocol = None
                    src_ports = parse_ports(arguments["<SRCPORTS>"])
                    dst_ports = parse_ports(arguments["<DSTPORTS>"])
                    position = arguments.get("--at")
                    if position is not None:
                        try:
                            position = int(position)
                        except ValueError:
                            sys.exit(1)
                    profile_rule_add_remove(
                        operation,
                        arguments["<PROFILE>"],
                        position,
                        action,
                        direction,
                        protocol=protocol,
                        icmp_type=arguments["<ICMPTYPE>"],
                        icmp_code=arguments["<ICMPCODE>"],
                        src_net=arguments["<SRCCIDR>"],
                        src_tag=arguments["<SRCTAG>"],
                        src_ports=src_ports,
                        dst_net=arguments["<DSTCIDR>"],
                        dst_tag=arguments["<DSTTAG>"],
                        dst_ports=dst_ports,
                    )
            elif arguments["add"]:
                profile_add(arguments["<PROFILE>"])
            elif arguments["remove"]:
                profile_remove(arguments["<PROFILE>"])
            elif arguments["show"]:
                profile_show(arguments["--detailed"])
        elif arguments["diags"]:
            save_diags(arguments["--log-dir"], arguments["--upload"])
        elif arguments["pool"]:
            if arguments["add"]:
                ip_pool_add(arguments["<CIDR>"],
                            ip_version,
                            arguments["--ipip"],
                            arguments["--nat-outgoing"])
            elif arguments["remove"]:
                ip_pool_remove(arguments["<CIDR>"], ip_version)
            elif arguments["show"]:
                if not ip_version:
                    ip_pool_show("v4")
                    ip_pool_show("v6")
                else:
                    ip_pool_show(ip_version)
        elif arguments["bgppeer"]:
            if arguments["add"]:
                bgppeer_add(arguments["<PEER_IP>"], ip_version,
                            arguments["<AS_NUM>"])
            elif arguments["remove"]:
                bgppeer_remove(arguments["<PEER_IP>"], ip_version)
            elif arguments["show"]:
                if not ip_version:
                    bgppeer_show("v4")
                    bgppeer_show("v6")
                else:
                    bgppeer_show(ip_version)
        elif arguments["container"]:
            if arguments["endpoint-id"]:
                container_endpoint_id_show(arguments["<CONTAINER>"])
            elif arguments["ip"]:
                if arguments["add"]:
                    container_ip_add(arguments["<CONTAINER>"],
                                     arguments["<IP>"],
                                     ip_version,
                                     arguments["--interface"])
                elif arguments["remove"]:
                    container_ip_remove(arguments["<CONTAINER>"],
                                        arguments["<IP>"],
                                        ip_version,
                                        arguments["--interface"])
                else:
                    if arguments["add"]:
                        container_add(arguments["<CONTAINER>"],
                                      arguments["<IP>"],
                                      arguments["--interface"])
                    if arguments["remove"]:
                        container_remove(arguments["<CONTAINER>"])
            else:
                if arguments["add"]:
                    container_add(arguments["<CONTAINER>"],
                                  arguments["<IP>"],
                                  arguments["--interface"])
                if arguments["remove"]:
                    container_remove(arguments["<CONTAINER>"])
        elif arguments["bgp-node-mesh"]:
            if arguments["on"] or arguments["off"]:
                set_bgp_node_mesh(arguments["on"])
            else:
                show_bgp_node_mesh()
        elif arguments["default-node-as"]:
            if arguments["<AS_NUM>"]:
                set_default_node_as(arguments["<AS_NUM>"])
            else:
                show_default_node_as()
    except SystemExit:
        raise
    except ConnectionError as e:
        # We hit a "Permission denied error (13) if the docker daemon does not
        # have sudo permissions
        if permission_denied_error(e):
            print_paragraph("Unable to run command.  Re-run the "
                            "command as root, or configure the docker group "
                            "to run with sudo privileges (see docker "
                            "installation guide for details).")
        else:
            print_paragraph("Unable to run docker commands. Is the docker "
                            "daemon running?")
        sys.exit(1)
    except DataStoreError as e:
        print_paragraph(e.message)
        sys.exit(1)
    except BaseException as e:
        print "Unexpected error executing command.\n"
        traceback.print_exc()
        sys.exit(1)
