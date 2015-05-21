#!/usr/bin/env python

"""calicoctl

Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:4001]

Usage:
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>]
  calicoctl node stop [--force]
  calicoctl status
  calicoctl shownodes [--detailed]
  calicoctl profile show [--detailed]
  calicoctl profile (add|remove) <PROFILE>
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update
  calicoctl profile <PROFILE> member add <CONTAINER>
  calicoctl pool (add|remove) <CIDR>
  calicoctl pool show [--ipv4 | --ipv6]
  calicoctl bgppeer rr (add|remove) <IP>
  calicoctl bgppeer rr show [--ipv4 | --ipv6]
  calicoctl container <CONTAINER> ip (add|remove) <IP> [--interface=<INTERFACE>]
  calicoctl container add <CONTAINER> <IP> [--interface=<INTERFACE>]
  calicoctl container remove <CONTAINER> [--force]
  calicoctl reset
  calicoctl diags
  calicoctl restart-docker-with-alternative-unix-socket
  calicoctl restart-docker-without-alternative-unix-socket

Options:
 --interface=<INTERFACE>  The name to give to the interface in the container
                          [default: eth1]
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:latest]
 --ipv4                   Show IPv4 information only.
 --ipv6                   Show IPv6 information only.
"""
import json
import os
import re
import socket
from subprocess import CalledProcessError
import sys
import textwrap
import time
import traceback

import netaddr
from docopt import docopt
import sh
import docker
import docker.utils
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from prettytable import PrettyTable

from calico_containers.adapter.datastore import (ETCD_AUTHORITY_ENV,
                                                 ETCD_AUTHORITY_DEFAULT,
                                                 Rules,
                                                 DataStoreError)
from calico_containers.adapter.docker_restart import REAL_SOCK, POWERSTRIP_SOCK
from calico_containers.adapter.ipam import IPAMClient
from calico_containers.adapter import netns, docker_restart
from requests.exceptions import ConnectionError
from urllib3.exceptions import MaxRetryError

hostname = socket.gethostname()
client = IPAMClient()
DOCKER_VERSION = "1.16"
docker_client = docker.Client(version=DOCKER_VERSION,
                              base_url=os.getenv("DOCKER_HOST",
                                                 "unix://var/run/docker.sock"))
docker_restarter = docker_restart.create_restarter()

try:
    sysctl = sh.Command._create("sysctl")
except sh.CommandNotFound as e:
    print "Missing command: %s" % e.message
    
DEFAULT_IPV4_POOL = IPNetwork("192.168.0.0/16")
DEFAULT_IPV6_POOL = IPNetwork("fd80:24e2:f998:72d6::/64")
POWERSTRIP_PORT = "2377"

class ConfigError(Exception):
    pass


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
        _ = client.get_ep_id_from_cont(hostname, container_id)
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
    endpoint = netns.set_up_endpoint(ip, pid, next_hops,
                                     veth_name=interface,
                                     proc_alias="/proc")

    # Register the endpoint
    client.set_endpoint(hostname, container_id, endpoint)

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
    container_id = get_container_id(container_name)

    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint_id = client.get_ep_id_from_cont(hostname, container_id)
    except KeyError:
        print "Container %s doesn't contain any endpoints" % container_name
        sys.exit(1)

    # Remove any IP address assignments that this endpoint has
    endpoint = client.get_endpoint(hostname, container_id, endpoint_id)
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
    netns.remove_endpoint(endpoint_id)

    # Remove the container from the datastore.
    client.remove_container(hostname, container_id)

    print "Removed Calico interface from %s" % container_name


def node_stop(force):
    if force or len(client.get_hosts()[hostname]["docker"]) == 0:
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


def node(ip, node_image, ip6=""):
    # modprobe and sysctl require root privileges.
    enforce_root()

    if not module_loaded("ip6_tables"):
        print >> sys.stderr, "module ip6_tables isn't loaded. Load with " \
                             "`modprobe ip6_tables`"
        sys.exit(2)

    if not module_loaded("xt_set"):
        print >> sys.stderr, "module xt_set isn't loaded. Load with " \
                             "`modprobe xt_set`"
        sys.exit(2)

    # Set up etcd
    ipv4_pools = client.get_ip_pools("v4")
    ipv6_pools = client.get_ip_pools("v6")

    # Create default pools if required
    if not ipv4_pools:
        client.add_ip_pool("v4", DEFAULT_IPV4_POOL)
    if not ipv6_pools:
        client.add_ip_pool("v6", DEFAULT_IPV6_POOL)

    client.ensure_global_config()
    client.create_host(hostname, ip, ip6)

    # Enable IP forwarding since all compute hosts are vRouters.
    # IPv4 forwarding should be enabled already by docker.
    sysctl("-w", "net.ipv4.ip_forward=1")
    sysctl("-w", "net.ipv6.conf.all.forwarding=1")

    if docker_restarter.is_using_alternative_socket():
        # At this point, docker is listening on a new port but powerstrip
        # might not be running, so docker clients need to talk directly to
        # docker.
        node_docker_client = docker.Client(version=DOCKER_VERSION,
                                           base_url="unix://%s" % REAL_SOCK)
        enable_socket = "YES"
    else:
        node_docker_client = docker_client
        enable_socket = "NO"

    try:
        node_docker_client.remove_container("calico-node", force=True)
    except docker.errors.APIError as err:
        if err.response.status_code != 404:
            raise

    etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)

    environment = [
        "POWERSTRIP_UNIX_SOCKET=%s" % enable_socket,
        "IP=%s" % ip,
        "IP6=%s" % ip6,
        "ETCD_AUTHORITY=%s" % etcd_authority,  # etcd host:port
        "FELIX_ETCDADDR=%s" % etcd_authority,  # etcd host:port
    ]

    binds = {
        "/var/run":
            {
                "bind": "/host-var-run",
                "ro": False
            },
        "/proc":
            {
                "bind": "/proc_host",
                "ro": False
            },
        "/var/log/calico":
            {
                "bind": "/var/log/calico",
                "ro": False
            }
    }

    host_config = docker.utils.create_host_config(
        privileged=True,
        restart_policy={"Name": "Always"},
        network_mode="host",
        binds=binds)

    _find_or_pull_node_image(node_image, node_docker_client)
    container = node_docker_client.create_container(
        node_image,
        name="calico-node",
        detach=True,
        environment=environment,
        host_config=host_config,
        volumes=["/host-var-run",
                 "/proc_host",
                 "/var/log/calico"])
    cid = container["Id"]

    node_docker_client.start(container)

    if enable_socket == "YES":
        while not os.path.exists(POWERSTRIP_SOCK):
            time.sleep(0.1)
        uid = os.stat(REAL_SOCK).st_uid
        gid = os.stat(REAL_SOCK).st_gid
        os.chown(POWERSTRIP_SOCK, uid, gid)
    else:
        print "Docker Remote API is on port %s.  Run \n" % POWERSTRIP_PORT
        print "export DOCKER_HOST=localhost:%s\n" % POWERSTRIP_PORT
        print "before using `docker run` for Calico networking.\n"

    print "Calico node is running with id: %s" % cid


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


def reset():
    print "Removing all data from data store"
    client.remove_all_data()


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


def profile_add_container(container_name, profile_name):
    """
    Add a container (on this host) to the profile with the given name.  This adds
    the first endpoint on the container to the profile.

    :param container_name: The Docker container name or ID.
    :param profile_name:  The Calico policy profile name.
    :return: None.
    """
    # Resolve the name to ID.
    container_id = get_container_id(container_name)

    if not client.profile_exists(profile_name):
        print "Profile with name %s was not found." % profile_name
        sys.exit(1)

    try:
        client.add_workload_to_profile(hostname, profile_name, container_id)
        print "Added %s to %s" % (container_name, profile_name)
    except KeyError:
        print "Failed to add container to profile.\n"
        print_container_not_in_calico_msg(container_name)
        sys.exit(1)


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
        x = PrettyTable(["Name", "Host", "Workload Type", "Workload ID",
                         "Endpoint ID", "State"])
        for name in profiles:
            members = client.get_profile_members(name)
            if not members:
                x.add_row([name, "None", "None", "None", "None", "None"])
                continue

            for host, ctypes in members.iteritems():
                for ctype, workloads in ctypes.iteritems():
                    for workload, endpoints in workloads.iteritems():
                        for ep_id, endpoint in endpoints.iteritems():
                            x.add_row([name,
                                       host,
                                       ctype,
                                       # Truncate ID to 12 chars like Docker
                                       workload[:12],
                                       ep_id,
                                       endpoint.state])
    else:
        x = PrettyTable(["Name"])
        for name in profiles:
            x.add_row([name])

    print str(x) + "\n"


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


def node_show(detailed):
    hosts = client.get_hosts()

    if detailed:
        x = PrettyTable(["Host", "Workload Type", "Workload ID", "Endpoint ID",
                         "Addresses", "MAC", "State"])
        for host, container_types in hosts.iteritems():
            if not container_types:
                x.add_row([host, "None", "None", "None",
                           "None", "None", "None"])
                continue
            for container_type, workloads in container_types.iteritems():
                for workload, endpoints in workloads.iteritems():
                    for ep_id, endpoint in endpoints.iteritems():
                        x.add_row([host,
                                   container_type,
                                   # Truncate ID to 12 chars like Docker
                                   workload[:12],
                                   ep_id,
                                   "\n".join([str(net) for net in
                                             endpoint.ipv4_nets |
                                             endpoint.ipv6_nets]),
                                   endpoint.mac,
                                   endpoint.state])
    else:
        x = PrettyTable(["Host", "Workload Type", "Number of workloads"])
        for host, container_types in hosts.iteritems():
            if not container_types:
                x.add_row([host, "N/A", "0"])
                continue
            for container_type, workloads in container_types.iteritems():
                x.add_row([host, container_type, len(workloads)])
    print str(x) + "\n"


def save_diags():
    """
    Gather Calico diagnostics for bug reporting.
    :return: None
    """
    # This needs to be run as root.
    enforce_root()

    script = """
#!/bin/bash
[ -z $BASH ] && echo "You must run this script in bash" && exit 1
whoami | grep -q "root" || { echo "You must run this script as root" && exit 1; }
echo "Collecting diags"

ROUTE_FILE=route
IPTABLES_PREFIX=iptables
IP6TABLES_PREFIX=ip6tables
CALICO_DIR=/var/log/calico
date=`date +"%F_%H-%M-%S"`
diags_dir=`mktemp -d`
system=`hostname`
echo "Using temp dir: $diags_dir"
pushd $diags_dir >/dev/null

echo DATE=$date > date
echo $system > hostname

echo "Dumping netstat output"
netstat -an > $diags_dir/netstat

echo "Dumping routes"
for cmd in "route -n" "ip route" "ip -6 route"
do
  echo $cmd >> $ROUTE_FILE
  $cmd >> $ROUTE_FILE
  echo >> $ROUTE_FILE
done
netstat -an > netstat

echo "Dumping iptables"
iptables-save > $IPTABLES_PREFIX
ipset list > ipset

echo "Copying Calico logs"
cp -a $CALICO_DIR .

echo "Dumping datastore"
curl -s -L http://127.0.0.1:4001/v2/keys/calico?recursive=true -o etcd_calico

FILENAME=diags-`date +%Y%m%d_%H%M%S`.tar.gz

tar -zcf $FILENAME *
echo "Diags saved to $FILENAME in $diags_dir"

echo "Uploading file. Available for 14 days from the URL printed when the upload completes"
curl --upload-file $FILENAME https://transfer.sh/$FILENAME

popd >/dev/null

echo "Done"
"""
    bash = sh.Command._create('bash')
    def process_output(line): sys.stdout.write(line)
    bash(_in=script, _err=process_output, _out=process_output).wait()
    # TODO: reimplement this in Python
    # TODO: ipset might not be installed on the host. But we don't want to
    # gather the diags in the container because it might not be running...


def ip_pool_add(cidr_pool, version):
    """
    Add the the given CIDR range to the IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :param version: v4 or v6
    :return: None
    """
    pool = check_ip_version(cidr_pool, version, IPNetwork)
    client.add_ip_pool(version, pool)


def ip_pool_remove(cidr_pool, version):
    """
    Add the the given CIDR range to the IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :param version: v4 or v6
    :return: None
    """
    pool = check_ip_version(cidr_pool, version, IPNetwork)
    try:
        client.remove_ip_pool(version, pool)
    except KeyError:
        print "%s is not a configured pool." % cidr_pool


def ip_pool_show(version):
    """
    Print a list of IP allocation pools.
    :return: None
    """
    assert version in ("v4", "v6")
    pools = client.get_ip_pools(version)
    x = PrettyTable(["IP%s CIDR" % version])
    for pool in pools:
        x.add_row([pool])
    print str(x) + "\n"


def restart_docker_with_alternative_unix_socket():
    """
    Update docker to use a different unix socket, so powerstrip can run
    its proxy on the "normal" one. This provides simple access for
    existing tools to the powerstrip proxy.

    Set the docker daemon to listen on the docker.real.sock by updating
    the config, clearing old sockets and restarting.
    """
    enforce_root()
    docker_restarter.restart_docker_with_alternative_unix_socket()


def restart_docker_without_alternative_unix_socket():
    """
    Remove any "alternative" unix socket config.
    """
    enforce_root()
    docker_restarter.restart_docker_without_alternative_unix_socket()


def bgppeer_add(ip, version):
    """
    Add the the given IP to the list of BGP Peers

    :param ip: The address to add
    :param version: v4 or v6
    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)
    client.add_bgp_peer(version, address)


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


def bgppeer_remove(ip, version):
    """
    Add the the given BGP Peer.

    :param ip: The address to use.
    :param version: v4 or v6
    :return: None
    """
    address = check_ip_version(ip, version, IPAddress)
    try:
        client.remove_bgp_peer(version, address)
    except KeyError:
        print "%s is not a configured peer." % address


def bgppeer_show(version):
    """
    Print a list BGP Peers
    """
    assert version in ("v4", "v6")
    peers = client.get_bgp_peers(version)
    if peers:
        heading = "IP%s BGP Peer" % version
        x = PrettyTable([heading], sortby=heading)
        for peer in peers:
            x.add_row([peer])
        x.align = "l"
        print str(x) + "\n"
    else:
        print "No IP%s BGP Peers defined.\n" % version


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
        endpoint_id = client.get_ep_id_from_cont(hostname, container_id)
        endpoint = client.get_endpoint(hostname, container_id, endpoint_id)
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
        old_endpoint = endpoint.copy()
        if address.version == 4:
            endpoint.ipv4_nets.add(IPNetwork(address))
        else:
            endpoint.ipv6_nets.add(IPNetwork(address))
        client.update_endpoint(hostname, container_id, old_endpoint, endpoint)
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
        old_endpoint = endpoint.copy()
        if address.version == 4:
            endpoint.ipv4_nets.remove(IPNetwork(address))
        else:
            endpoint.ipv6_nets.remove(IPNetwork(address))
        client.update_endpoint(hostname, container_id, old_endpoint, endpoint)
        client.unassign_address(pool, ip)
        sys.exit(1)

    print "IP %s added to %s" % (ip, container_name)


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
        endpoint_id = client.get_ep_id_from_cont(hostname, container_id)
        endpoint = client.get_endpoint(hostname, container_id, endpoint_id)
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
        old_endpoint = endpoint.copy()
        nets.remove(IPNetwork(address))
        client.update_endpoint(hostname, container_id, old_endpoint, endpoint)
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


def validate_arguments():
    """
    Validate common argument values.
    """
    profile_ok = (arguments["<PROFILE>"] is None or
                  re.match("^\w{1,30}$", arguments["<PROFILE>"]))
    tag_ok = (arguments["<TAG>"] is None or
              re.match("^\w+$", arguments["<TAG>"]))
    ip_ok = arguments["--ip"] is None or netaddr.valid_ipv4(arguments["--ip"])
    ip6_ok = arguments["--ip6"] is None or \
             netaddr.valid_ipv6(arguments["--ip6"])
    container_ip_ok = arguments["<IP>"] is None or \
                      netaddr.valid_ipv4(arguments["<IP>"]) or \
                      netaddr.valid_ipv6(arguments["<IP>"])
    cidr_ok = True
    if arguments["<CIDR>"]:
        try:
            IPNetwork(arguments["<CIDR>"])
        except AddrFormatError:
            cidr_ok = False

    if not profile_ok:
        print_paragraph("Profile names must be <30 character long and can "
                        "only contain numbers, letters and underscores.")
    if not tag_ok:
        print "Tags names can only container numbers, letters and underscores."
    if not ip_ok:
        print "Invalid IPv4 address specified with --ip argument."
    if not ip6_ok:
        print "Invalid IPv6 address specified with --ip6 argument."
    if not container_ip_ok:
        print "Invalid IP address specified."
    if not cidr_ok:
        print "Invalid CIDR specified."

    if not (profile_ok and ip_ok and ip6_ok and tag_ok and
                container_ip_ok and cidr_ok):
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
    print_paragraph("Container %s is unknown to Calico.  This can occur if "
                    "the container was created without setting the powerstrip "
                    "port (%s) either in the DOCKER_HOST environment variable "
                    "or using the -H flag on the `docker` command." %
                    (container_name, POWERSTRIP_PORT))
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


if __name__ == '__main__':
    arguments = docopt(__doc__)

    validate_arguments()
    ip_version = get_container_ipv_from_arguments()

    try:
        if arguments["restart-docker-with-alternative-unix-socket"]:
            restart_docker_with_alternative_unix_socket()
        elif arguments["restart-docker-without-alternative-unix-socket"]:
            restart_docker_without_alternative_unix_socket()
        elif arguments["node"]:
            if arguments["stop"]:
                node_stop(arguments["--force"])
            else:
                node_image = arguments['--node-image']
                ip6 = arguments["--ip6"]
                node(arguments["--ip"],
                     node_image=node_image,
                     ip6=ip6)
        elif arguments["status"]:
            status()
        elif arguments["reset"]:
            reset()
        elif arguments["profile"]:
            if arguments["tag"]:
                if arguments["show"]:
                    profile_tag_show(arguments["<PROFILE>"])
                elif arguments["add"]:
                    profile_tag_add(arguments["<PROFILE>"],
                                    arguments["<TAG>"])
                elif arguments["remove"]:
                    profile_tag_remove(arguments["<PROFILE>"],
                                       arguments["<TAG>"])
            elif arguments["member"]:
                profile_add_container(arguments["<CONTAINER>"],
                                      arguments["<PROFILE>"])
            elif arguments["rule"]:
                if arguments["show"]:
                    profile_rule_show(arguments["<PROFILE>"],
                                      human_readable=True)
                elif arguments["json"]:
                    profile_rule_show(arguments["<PROFILE>"],
                                      human_readable=False)
                elif arguments["update"]:
                    profile_rule_update(arguments["<PROFILE>"])
            elif arguments["add"]:
                profile_add(arguments["<PROFILE>"])
            elif arguments["remove"]:
                profile_remove(arguments["<PROFILE>"])
            elif arguments["show"]:
                profile_show(arguments["--detailed"])
        elif arguments["diags"]:
            save_diags()
        elif arguments["shownodes"]:
            node_show(arguments["--detailed"])
        elif arguments["pool"]:
            if arguments["add"]:
                ip_pool_add(arguments["<CIDR>"], ip_version)
            elif arguments["remove"]:
                ip_pool_remove(arguments["<CIDR>"], ip_version)
            elif arguments["show"]:
                if not ip_version:
                    ip_pool_show("v4")
                    ip_pool_show("v6")
                else:
                    ip_pool_show(ip_version)
        elif arguments["bgppeer"] and arguments["rr"]:
            if arguments["add"]:
                bgppeer_add(arguments["<IP>"], ip_version)
            elif arguments["remove"]:
                bgppeer_remove(arguments["<IP>"], ip_version)
            elif arguments["show"]:
                if not ip_version:
                    bgppeer_show("v4")
                    bgppeer_show("v6")
                else:
                    bgppeer_show(ip_version)
        elif arguments["container"]:
            if arguments["ip"]:
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
            elif arguments["container"]:
                if arguments["add"]:
                    container_add(arguments["<CONTAINER>"],
                                  arguments["<IP>"],
                                  arguments["--interface"])
                if arguments["remove"]:
                    container_remove(arguments["<CONTAINER>"])
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
        print dir(e)
        sys.exit(1)

