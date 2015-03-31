#!/usr/bin/env python
"""calicoctl

Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:4001]

Usage:
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>] [--force-unix-socket]
  calicoctl node stop [--force]
  calicoctl status
  calicoctl shownodes [--detailed]
  calicoctl profile show [--detailed]
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile add <PROFILE>
  calicoctl profile remove <PROFILE>
  calicoctl profile addmember <PROFILE> <CONTAINER>
  calicoctl ipv4 pool add <CIDR>
  calicoctl ipv4 pool del <CIDR>
  calicoctl ipv4 pool show
  calicoctl ipv6 pool add <CIDR>
  calicoctl ipv6 pool del <CIDR>
  calicoctl ipv6 pool show
  calicoctl container add <CONTAINER> <IP>
  calicoctl container remove <CONTAINER> [--force]
  calicoctl reset
  calicoctl diags

Options:
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:latest]

"""
import socket
import sys
import time
import os
import re
import json

import netaddr
from docopt import docopt
import sh
import docker
import docker.utils
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from prettytable import PrettyTable

from node.adapter.datastore import (DatastoreClient,
                                    ETCD_AUTHORITY_ENV,
                                    ETCD_AUTHORITY_DEFAULT)
from node.adapter import netns


hostname = socket.gethostname()
client = DatastoreClient()
DOCKER_VERSION = "1.16"
docker_client = docker.Client(version=DOCKER_VERSION,
                              base_url=os.getenv("DOCKER_HOST",
                                                 "unix://var/run/docker.sock"))

try:
    modprobe = sh.Command._create('modprobe')
    sysctl = sh.Command._create("sysctl")
    restart = sh.Command._create("restart")
except sh.CommandNotFound as e:
    print "Missing command: %s" % e.message
    
DEFAULT_IPV4_POOL = IPNetwork("192.168.0.0/16")
DEFAULT_IPV6_POOL = IPNetwork("fd80:24e2:f998:72d6::/64")

REAL_SOCK = "/var/run/docker.real.sock"
POWERSTRIP_SOCK = "/var/run/docker.sock"
DOCKER_DEFAULT_FILENAME = "/etc/default/docker"
DOCKER_OPTIONS = 'DOCKER_OPTS="-H unix://%s"' % REAL_SOCK

def get_container_info(container_name):
    """
    Get the full container info array from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container info array
    """
    try:
        info = docker_client.inspect_container(container_name)
    except docker.errors.APIError as e:
        if e.response.status_code == 404:
            # Re-raise as a key error for consistency.
            raise KeyError("Container %s was not found." % container_name)
        else:
            raise
    return info

def get_container_id(container_name):
    """
    Get the full container ID from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container ID as a string.
    """
    info = get_container_info(container_name)
    return info["Id"]


class ConfigError(Exception):
    pass


def container_add(container_name, ip):
    """
    Add a container (on this host) to Calico networking with the given IP.

    :param container_name: The name or ID of the container.
    :param ip: An IPAddress object with the desired IP to assign.
    """
    try:
        info = get_container_info(container_name)
    except KeyError as err:
        print err.message
        sys.exit(1)
    container_id = info["Id"]

    # Check if the container already exists
    try:
        _ = client.get_ep_id_from_cont(container_id)
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

    # Check the IP is in the allocation pool.  If it isn't, BIRD won't export
    # it.
    ip = IPAddress(ip)
    version = "v%s" % ip.version
    pools = client.get_ip_pools(version)
    if not any([ip in pool for pool in pools]):
        print "%s is not in any configured pools" % ip
        sys.exit(1)

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name
        sys.exit(1)

    # The next hop IPs for this host are stored in etcd.
    next_hops = client.get_default_next_hops(hostname)
    try:
        next_hops[ip.version]
    except KeyError:
        print "This node is not configured for IPv%d." % ip.version
        sys.exit(1)

    # Actually configure the netns.  Use eth1 since eth0 is the docker bridge.
    pid = info["State"]["Pid"]
    endpoint = netns.set_up_endpoint(ip, pid, next_hops,
                                     veth_name="eth1",
                                     proc_alias="proc")

    # Register the endpoint
    client.create_container(hostname, container_id, endpoint)

    print "IP %s added to %s" % (ip, container_name)


def container_remove(container_name):
    """
    Remove a container (on this host) from Calico networking.

    The container may be left in a state without any working networking.
    If there is a network adaptor in the host namespace used by the container
    then it is removed.

    :param container_name: The name or ID of the container.
    """
    # Resolve the name to ID.
    container_id = get_container_id(container_name)

    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint_id = client.get_ep_id_from_cont(container_id)
    except KeyError:
        print "Container %s doesn't contain any endpoints" % container_name
        return

    # Remove the endpoint
    netns.remove_endpoint(endpoint_id)

    # Remove the container from the datastore.
    client.remove_container(container_id)

    print "Removed Calico interface from %s" % container_name


def node_stop(force):
    if force or len(client.get_hosts()[hostname]["docker"]) == 0:
        client.remove_host()
        try:
            docker_client.stop("calico-node")
        except docker.errors.APIError as err:
            if err.response.status_code != 404:
                raise

        print "Node stopped and all configuration removed"
    else:
        print "Current host has active endpoints so can't be stopped." + \
              " Force with --force"


def clean_restart_docker(sock_to_wait_on):
    if os.path.exists(REAL_SOCK):
        os.remove(REAL_SOCK)
    if os.path.exists(POWERSTRIP_SOCK):
        os.remove(POWERSTRIP_SOCK)

    restart("docker")

    # Wait for docker to create the socket
    while not os.path.exists(sock_to_wait_on):
        time.sleep(0.1)


def node(ip, force_unix_socket, node_image, ip6=""):
    # modprobe and sysctl require root privileges.
    if os.geteuid() != 0:
        print >> sys.stderr, "`calicoctl node` must be run as root."
        sys.exit(2)

    modprobe("ip6_tables")
    modprobe("xt_set")

    # Set up etcd
    ipv4_pools = client.get_ip_pools("v4")
    ipv6_pools = client.get_ip_pools("v6")

    # Create default pools if required
    if not ipv4_pools:
        client.add_ip_pool("v4", DEFAULT_IPV4_POOL)
    if not ipv6_pools:
        client.add_ip_pool("v6", DEFAULT_IPV6_POOL)

    client.create_global_config()
    client.create_host(ip, ip6)

    # Enable IP forwarding since all compute hosts are vRouters.
    sysctl("-w", "net.ipv4.ip_forward=1")
    sysctl("-w", "net.ipv6.conf.all.forwarding=1")

    # The docker daemon could be in one of two states:
    # 1) Listening on /var/run/docker.sock - the default
    # 2) listening on /var/run/docker.real.sock - if it's been previously run
    #    with --force-unix-socket
    enable_socket = "NO"

    # We might need to talk to a different docker endpoint, so create some
    # client flexibility.
    node_docker_client = docker_client

    if force_unix_socket:
        # Update docker to use a different unix socket, so powerstrip can run
        # its proxy on the "normal" one. This provides simple access for
        # existing tools to the powerstrip proxy.

        # Set the docker daemon to listen on the docker.real.sock by updating
        # the config, clearing old sockets and restarting.
        socket_config_exists = \
            DOCKER_OPTIONS in open(DOCKER_DEFAULT_FILENAME).read()
        if not socket_config_exists:
            with open(DOCKER_DEFAULT_FILENAME, "a") as docker_config:
                docker_config.write(DOCKER_OPTIONS)
            clean_restart_docker(REAL_SOCK)

        # Always remove the socket that powerstrip will use, as it gets upset
        # otherwise.
        if os.path.exists(POWERSTRIP_SOCK):
            os.remove(POWERSTRIP_SOCK)

        # At this point, docker is listening on a new port but powerstrip isn't
        # running, so docker clients need to talk directly to docker.
        node_docker_client = docker.Client(version=DOCKER_VERSION,
                                           base_url="unix://%s" % REAL_SOCK)
        enable_socket = "YES"
    else:
        # Not using the unix socket.  If there is --force-unix-socket config in
        # place, do some cleanup
        socket_config_exists = \
            DOCKER_OPTIONS in open(DOCKER_DEFAULT_FILENAME).read()
        if socket_config_exists:
            good_lines = [line for line in open(DOCKER_DEFAULT_FILENAME)
                          if DOCKER_OPTIONS not in line]
            open(DOCKER_DEFAULT_FILENAME, 'w').writelines(good_lines)
            clean_restart_docker(POWERSTRIP_SOCK)

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

    if force_unix_socket:
        while not os.path.exists(POWERSTRIP_SOCK):
            time.sleep(1)
        uid = os.stat(REAL_SOCK).st_uid
        gid = os.stat(REAL_SOCK).st_gid
        os.chown(POWERSTRIP_SOCK, uid, gid)
    else:
        powerstrip_port = "2377"
        print "Docker Remote API is on port %s.  Run \n" % powerstrip_port
        print "export DOCKER_HOST=localhost:%s\n" % powerstrip_port
        print "before using `docker run` for Calico networking.\n"

    print "Calico node is running with id: %s" % cid


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

        apt_output = docker_client.execute("calico-node", ["/bin/bash", "-c",
                                           "apt-cache policy calico-felix"])
        result = re.search(r"Installed: (.*?)\s", apt_output)
        if result is not None:
            print "Running felix version %s" % result.group(1)

        print "IPv4 Bird (BGP) status"
        print(docker_client.execute("calico-node",
                                    ["/bin/bash", "-c",
                                     "echo show protocols | "
                                     "birdc -s /etc/service/bird/bird.ctl"]))
        print "IPv6 Bird (BGP) status"
        print(docker_client.execute("calico-node",
                                    ["/bin/bash", "-c",
                                     "echo show protocols | "
                                     "birdc6 -s "
                                     "/etc/service/bird6/bird6.ctl"]))


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
        print "Group %s already exists." % profile_name
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
        print "Group with name %s was not found." % profile_name
        return

    client.add_workload_to_profile(profile_name, container_id)
    print "Added %s to %s" % (container_name, profile_name)


def profile_remove(profile_name):
    # TODO - Don't allow removing a profile that has endpoints in it.
    try:
        client.delete_profile(profile_name)
    except KeyError:
        print "Couldn't find profile with name %s" % profile_name
    else:
        print "Deleted profile %s" % profile_name


def profile_show(detailed):
    profiles = client.get_profile_names()

    if detailed:
        x = PrettyTable(["Name", "Endpoint ID"])
        for name in profiles:
            members = client.get_profile_members(name)
            if members:
                for member in members:
                    x.add_row([name, member])
            else:
                x.add_row([name, "No members"])
    else:
        x = PrettyTable(["Name"])
        for name in profiles:
            x.add_row([name])

    print x


def profile_tag_show(name):
    """Show the tags on the profile."""
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    for tag in profile.tags:
        print tag


def profile_rule_show(name, human_readable=False):
    """Show the rules on the profile."""
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if human_readable:
        print "Inbound rules:"
        i = 1
        for rule in profile.rules.inbound_rules:
            print " %3d %s" % (i, rule.pprint())
            i += 1
        print "Outbound rules:"
        i = 1
        for rule in profile.rules.outbound_rules:
            print " %3d %s" % (i, rule.pprint())
            i += 1
    else:
        json.dump(profile.rules._asdict(),
                  sys.stdout,
                  indent=2)
        print ""


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
                    for endpoint, data in endpoints.iteritems():
                        x.add_row([host,
                                   container_type,
                                   workload,
                                   endpoint,
                                   " ".join(data["addrs"]),
                                   data["mac"],
                                   data["state"]])
    else:
        x = PrettyTable(["Host", "Workload Type", "Number of workloads"])
        for host, container_types in hosts.iteritems():
            if not container_types:
                x.add_row([host, "N/A", "0"])
                continue
            for container_type, workloads in container_types.iteritems():
                x.add_row([host, container_type, len(workloads)])
    print x


def save_diags():
    """
    Gather Calico diagnostics for bug reporting.
    :return: None
    """
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
    bash(_in=script, _err=process_output, _out=process_output).wait()
    # TODO: reimplement this in Python
    # TODO: ipset might not be installed on the host. But we don't want to
    # gather the diags in the container because it might not be running...


def ip_pool_add(cidr_pool, version):
    """
    Add the the given CIDR range to the IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :return: None
    """
    assert version in (4, 6)
    try:
        pool = IPNetwork(cidr_pool)
    except AddrFormatError:
        print "%s is not a valid IP prefix." % cidr_pool
        return
    if pool.version != version:
        print "%s is an IPv%d prefix, this command is for IPv%d." % \
              (cidr_pool, pool.version, version)
        return
    client.add_ip_pool("v%d" % version, pool)


def ip_pool_remove(cidr_pool, version):
    """
    Add the the given CIDR range to the IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :return: None
    """
    assert version in (4, 6)
    try:
        pool = IPNetwork(cidr_pool)
    except AddrFormatError:
        print "%s is not a valid IP prefix." % cidr_pool
        return
    if pool.version != version:
        print "%s is an IPv%d prefix, this command is for IPv%d." % \
              (cidr_pool, pool.version, version)
        return
    try:
        client.del_ip_pool("v%d" % version, pool)
    except KeyError:
        print "%s is not a configured pool." % cidr_pool


def ip_pool_show(version):
    """
    Print a list of IP allocation pools.
    :return: None
    """
    pools = client.get_ip_pools(version)
    x = PrettyTable(["CIDR"])
    for pool in pools:
        x.add_row([pool])
    print x


def validate_arguments():
    profile_ok = (arguments["<PROFILE>"] is None or
                re.match("^\w{1,30}$", arguments["<PROFILE>"]))
    ip_ok = arguments["--ip"] is None or netaddr.valid_ipv4(
        arguments["--ip"]) or netaddr.valid_ipv6(arguments["--ip"])
    container_ip_ok = arguments["<IP>"] is None or netaddr.valid_ipv4(
        arguments["<IP>"]) or netaddr.valid_ipv6(arguments["<IP>"])

    if not profile_ok:
        print "Groups must be <30 character long and can only container " \
              "numbers, letters and underscore."
    if not ip_ok:
        print "Invalid ip argument"
    return profile_ok and ip_ok and container_ip_ok


def process_output(line):
    sys.stdout.write(line)


if __name__ == '__main__':
    arguments = docopt(__doc__)
    if validate_arguments():
        if arguments["node"]:
            if arguments["stop"]:
                node_stop(arguments["--force"])
            else:
                node_image = arguments['--node-image']
                ip6 = arguments["--ip6"]
                node(arguments["--ip"],
                     arguments["--force-unix-socket"],
                     node_image=node_image,
                     ip6=ip6)
        elif arguments["status"]:
            status()
        elif arguments["reset"]:
            reset()
        elif arguments["profile"]:
            if arguments["add"]:
                profile_add(arguments["<PROFILE>"])
            elif arguments["remove"]:
                profile_remove(arguments["<PROFILE>"])
            elif arguments["tag"]:
                profile_tag_show(arguments["<PROFILE>"])
            elif arguments["rule"]:
                if arguments["show"]:
                    profile_rule_show(arguments["<PROFILE>"],
                                      human_readable=True)
                elif arguments["json"]:
                    profile_rule_show(arguments["<PROFILE>"],
                                      human_readable=False)
            elif arguments["show"]:
                profile_show(arguments["--detailed"])
            elif arguments["addmember"]:
                profile_add_container(arguments["<CONTAINER>"],
                                    arguments["<PROFILE>"])
        elif arguments["diags"]:
            save_diags()
        elif arguments["shownodes"]:
            node_show(arguments["--detailed"])
        elif arguments["ipv4"]:
            assert arguments["pool"]
            if arguments["add"]:
                ip_pool_add(arguments["<CIDR>"], version=4)
            elif arguments["del"]:
                ip_pool_remove(arguments["<CIDR>"], version=4)
            elif arguments["show"]:
                ip_pool_show("v4")
        elif arguments["ipv6"]:
            assert arguments["pool"]
            if arguments["add"]:
                ip_pool_add(arguments["<CIDR>"], version=6)
            elif arguments["del"]:
                ip_pool_remove(arguments["<CIDR>"], version=6)
            elif arguments["show"]:
                ip_pool_show("v6")
        if arguments["container"]:
            if arguments["add"]:
                container_add(arguments["<CONTAINER>"], arguments["<IP>"])
            if arguments["remove"]:
                container_remove(arguments["<CONTAINER>"])
    else:
        print "Couldn't validate arguments. Exiting."
        sys.exit(1)
