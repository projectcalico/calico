#!/usr/bin/env python
"""calicoctl

Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:4001]

Usage:
  calicoctl master --ip=<IP> [--master-image=<DOCKER_IMAGE_NAME>]
  calicoctl master stop [--force]
  calicoctl node --ip=<IP> [--node-image=<DOCKER_IMAGE_NAME>] [--ip6=<IP6>]
  calicoctl node stop [--force]
  calicoctl status
  calicoctl shownodes [--detailed]
  calicoctl group show [--detailed]
  calicoctl group add <GROUP>
  calicoctl group remove <GROUP>
  calicoctl group addmember <GROUP> <CONTAINER>
  calicoctl group removemember <GROUP> <CONTAINER>
  calicoctl ipv4 pool add <CIDR>
  calicoctl ipv4 pool del <CIDR>
  calicoctl ipv4 pool show
  calicoctl container add <CONTAINER> <IP>
  calicoctl container remove <CONTAINER> [--force]
  calicoctl reset
  calicoctl diags

Options:
 --ip=<IP>                The local management address to use.
 --ip6=<IP6>              The local IPv6 management address to use.
 --master-image=<DOCKER_IMAGE_NAME>  Docker image to use for
                          Calico's master container
                          [default: calico/master:latest]
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:latest]

"""
import socket
from subprocess import call, check_output, CalledProcessError
import sys
import uuid
import StringIO

from datastore import DatastoreClient, ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT
import netaddr
import os
import re
from docopt import docopt
import sh
import docker as pydocker
from netaddr import IPNetwork, IPAddress
from netaddr.core import AddrFormatError
from prettytable import PrettyTable
from node.root_overlay.adapter import netns


hostname = socket.gethostname()
mkdir = sh.Command._create('mkdir')
docker = sh.Command._create('docker')
modprobe = sh.Command._create('modprobe')
grep = sh.Command._create('grep')
sysctl = sh.Command._create("sysctl")

mkdir_p = mkdir.bake('-p')

DEFAULT_IPV4_POOL = IPNetwork("192.168.0.0/16")
DEFAULT_IPV6_POOL = IPNetwork("fd80:24e2:f998:72d6::/64")


def get_container_info(container_name):
    """
    Get the full container info array from a partial ID or name.

    :param container_name: The partial ID or name of the container.
    :return: The container info array
    """
    docker_client = pydocker.Client(version="1.16")
    try:
        info = docker_client.inspect_container(container_name)
    except pydocker.errors.APIError as e:
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
    client = DatastoreClient()

    info = get_container_info(container_name)
    container_id = info["Id"]

    # Check if the container already exists
    try:
        _ = client.get_ep_id_from_cont(container_id)
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        # Calico already set up networking for this container.  Since we got called with an
        # IP address, we shouldn't just silently exit, since that would confuse the user:
        # the container would not be reachable on that IP address.  So, raise an exception.
        print "%s has already been configured with Calico Networking." % container_name

    # Check the IP is in the allocation pool.  If it isn't, BIRD won't export it.
    ip = IPAddress(ip)
    version = "v%s" % ip.version
    pools = client.get_ip_pools(version)
    if not any([ip in pool for pool in pools]):
        print "%s is not in any configured pools" % ip

    # Check the container is actually running.
    if not info["State"]["Running"]:
        print "%s is not currently running." % container_name

    # Actually configure the netns.  Use eth1 since eth0 is the docker bridge.
    pid = info["State"]["Pid"]
    endpoint = netns.set_up_endpoint(ip, pid, veth_name="eth1", proc_alias="proc")

    # Register the endpoint
    client.create_container(hostname, container_id, endpoint)

    print "IP %s added to %s" % (ip, container_name)


def container_remove(container_name):
    """
    Remove a container (on this host) from Calico networking.

    The container may be left in a state without any working networking.
    The container can't be removed if there are ACLs that refer to it.
    If there is a network adaptor in the host namespace used by the container then it's
    removed.

    :param container_name: The name or ID of the container.
    """
    # Resolve the name to ID.
    client = DatastoreClient()
    container_id = get_container_id(container_name)

    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint_id = client.get_ep_id_from_cont(container_id)
    except KeyError:
        print "Container %s doesn't contain any endpoints" % container_name
        return

    groups = client.get_groups_by_endpoint(endpoint_id)
    if len(groups) > 0:
        print "Container %s is in security groups %s. Can't remove." % (container_name, groups)

    # Remove the endpoint
    netns.remove_endpoint(endpoint_id)

    # Remove the container from the datastore.
    client.remove_container(container_id)

    print "Removed Calico interface from %s" % container_name

def group_remove_container(container_name, group_name):
    """
    Add a container (on this host) to the group with the given name.  This adds the first
    endpoint on the container to the group.

    :param container_name: The Docker container name or ID.
    :param group_name:  The Calico security group name.
    :return: None.
    """
    client = DatastoreClient()

    # Resolve the name to ID.
    container_id = get_container_id(container_name)

    # Get the group UUID.
    group_id = client.get_group_id(group_name)
    if not group_id:
        print "Group with name %s was not found." % group_name
    else:
        endpoint_id = client.get_ep_id_from_cont(container_id)

        try:
            # Remove the endpoint from the group.
            client.remove_endpoint_from_group(group_id, endpoint_id)
            print "Remove %s from %s" % (container_name, group_name)
        except KeyError:
            print "%s is not a member of %s" % (container_name, group_name)
            sys.exit(1)

def node_stop(force):
    client = DatastoreClient()
    if force or len(client.get_hosts()[hostname]["docker"]) == 0:
        client.remove_host()

        # This next line can fail, since the container is needed for the connection to
        # docker.
        try:
            docker("stop", "calico-node")
        except Exception:
            pass
        print "Node stopped and all configuration removed"
    else:
        print "Current host has active endpoints so can't be stopped. Force with --force"


def node(ip, node_image, ip6=""):
    create_dirs()
    modprobe("ip6_tables")
    modprobe("xt_set")

    # Set up etcd
    client = DatastoreClient()

    # Enable IP forwarding.
    sysctl("-w", "net.ipv4.ip_forward=1")
    sysctl("-w", "net.ipv6.conf.all.forwarding=1")

    master_ip = client.get_master()
    if not master_ip:
        print "No master can be found. Exiting"
        return

    ipv4_pools = client.get_ip_pools("v4")
    if not ipv4_pools:
        print "No IPv4 range defined.  Exiting."
        return
    ipv6_pools = client.get_ip_pools("v6")
    if not ipv6_pools:
        print "No IPv6 range defined.  Exiting."
        return

    print "Using master on IP: %s" % master_ip
    client.create_host(ip, ip6)
    try:
        docker("rm", "-f", "calico-node")
    except Exception:
        pass

    etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
    output = StringIO.StringIO()

    docker("run", "-e",  "IP=%s" % ip,
                  "-e",  "IP6=%s" % ip6,
                  "--name=calico-node",
                  "--restart=always",
                  "--privileged",
                  "--net=host",  # BIRD/Felix can manipulate the base networking stack
                  "-v", "/var/run/docker.sock:/var/run/docker.sock",  # Powerstrip access Docker
                  "-v", "/proc:/proc_host",  # Powerstrip Calico needs access to proc to set up
                                             # networking
                  "-v", "/var/log/calico:/var/log/calico",  # Logging volume
                  "-e", "ETCD_AUTHORITY=%s" % etcd_authority,  # etcd host:port
                  "-d",
                  node_image, _err=process_output, _out=output).wait()

    cid = output.getvalue().strip()
    output.close()
    powerstrip_port = "2377"
    print "Calico node is running with id: %s" % cid
    print "Docker Remote API is on port %s.  Run \n" % powerstrip_port
    print "export DOCKER_HOST=localhost:%s\n" % powerstrip_port
    print "before using `docker run` for Calico networking.\n"


def master_stop(force):
    client = DatastoreClient()
    if force or len(client.get_hosts()) == 0:
        client.remove_master()
        docker("stop", "calico-master")
        print "Master stopped and all configuration removed"
    else:
        print "Hosts exist so master can't be stopped. Force with --force"


def master(ip, master_image):
    create_dirs()

    # Add IP to etcd
    client = DatastoreClient()
    client.set_master(ip)

    # If no IPv4 pools are defined, add a default.
    ipv4_pools = client.get_ip_pools("v4")
    if len(ipv4_pools) == 0:
        client.add_ip_pool("v4", DEFAULT_IPV4_POOL)
    # If no IPv6 pools are defined, add a default.
    ipv6_pools = client.get_ip_pools("v6")
    if len(ipv6_pools) == 0:
        client.add_ip_pool("v6", DEFAULT_IPV6_POOL)

    try:
        docker("rm", "-f", "calico-master")
    except Exception:
        pass

    etcd_authority = os.getenv(ETCD_AUTHORITY_ENV, ETCD_AUTHORITY_DEFAULT)
    output = StringIO.StringIO()
    
    # Start the container
    docker("run", "--name=calico-master",
                  "--restart=always",
                  "--privileged",
                  "--net=host",
                  "-v", "/var/log/calico:/var/log/calico",  # Logging volume
                  "-e", "ETCD_AUTHORITY=%s" % etcd_authority,  # etcd host:port
                  "-d",
                  master_image, _err=process_output, _out=output).wait()
    cid = output.getvalue().strip()
    output.close()
    print "Calico master is running with id: %s" % cid


def status():
    client = DatastoreClient()
    print "Currently configured master is %s" % client.get_master()

    try:
        print(grep(docker("ps"), "-i", "calico"))
    except Exception:
        print "No calico containers appear to be running"

    try:
        print(docker("exec", "calico-master", "/bin/bash", "-c", "apt-cache policy "
                                                                 "calico-felix"))
    except Exception:
        print "Skipping felix version information as Calico node isn't running"

    #If bird is running, then print bird.
    try:
        print(docker("exec", "calico-node", "/bin/bash",  "-c", "echo show protocols | birdc -s "
                                                            "/etc/service/bird/bird.ctl"))
        print(docker("exec", "calico-node", "/bin/bash",  "-c", "echo show protocols | birdc6 -s "
                                                                "/etc/service/bird6/bird6.ctl"))
    except Exception:
        print "Couldn't collect BGP Peer information"


def reset():
    client = DatastoreClient()

    print "Removing all data from datastore"
    client.remove_all_data()

    docker("kill", "calico-node")
    docker("kill", "calico-master")

    try:
        interfaces_raw = check_output("ip link show | grep -Eo ' (tap(.*?)):' |grep -Eo '[^ :]+'",
                                      shell=True)
        print "Removing interfaces:\n%s" % interfaces_raw
        interfaces = interfaces_raw.splitlines()
        for interface in interfaces:
            call("ip link delete %s" % interface, shell=True)
    except CalledProcessError:
        print "No interfaces to clean up"


def group_add(group_name):
    """
    Create a security group with the given name.
    :param group_name: The name for the group.
    :return: None.
    """
    client = DatastoreClient()
    # Check if the group exists.
    if client.get_group_id(group_name):
        print "Group %s already exists." % group_name
    else:
        # Create the group.
        group_id = uuid.uuid1().hex
        client.create_group(group_id, group_name)
        print "Created group %s with ID %s" % (group_name, group_id)


def group_add_container(container_name, group_name):
    """
    Add a container (on this host) to the group with the given name.  This adds the first
    endpoint on the container to the group.

    :param container_name: The Docker container name or ID.
    :param group_name:  The Calico security group name.
    :return: None.
    """
    client = DatastoreClient()
    # Resolve the name to ID.
    container_id = get_container_id(container_name)

    # Get the group UUID.
    group_id = client.get_group_id(group_name)
    if not group_id:
        print "Group with name %s was not found." % group_name
        return

    endpoint_id = client.get_ep_id_from_cont(container_id)
    client.add_endpoint_to_group(group_id, endpoint_id)
    print "Added %s to %s" % (container_name, group_name)

def group_remove(group_name):
    #TODO - Don't allow removing a group that has enpoints in it.
    client = DatastoreClient()
    group_id = client.delete_group(group_name)
    if group_id:
        print "Deleted group %s with ID %s" % (group_name, group_id)
    else:
        print "Couldn't find group with name %s" % group_name


def group_show(detailed):
    client = DatastoreClient()
    groups = client.get_groups()

    if detailed:
        x = PrettyTable(["ID", "Name", "Container ID"])
        for group_id, name in groups.iteritems():
            members = client.get_group_members(group_id)
            if members:
                for member in members:
                    x.add_row([group_id, name, member])
            else:
                x.add_row([group_id, name, "No members"])
    else:
        x = PrettyTable(["ID", "Name"])
        for group_id, name in groups.iteritems():
            x.add_row([group_id, name])

    print x


def node_show(detailed):
    client = DatastoreClient()
    hosts = client.get_hosts()

    if detailed:
        x = PrettyTable(["Host", "Workload Type", "Workload ID", "Endpoint ID", "Addresses",
                         "MAC", "State"])
        for host, container_types in hosts.iteritems():
            if not container_types:
                x.add_row([host, "None", "None", "None", "None", "None", "None"])
                continue
            for container_type, workloads in container_types.iteritems():
                for workload, endpoints in workloads.iteritems():
                    for endpoint, data in endpoints.iteritems():
                        x.add_row([host, container_type, workload, endpoint, data["addrs"], data["mac"],
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
    # TODO: ipset might not be installed on the host. But we don't want to gather the diags in
    # the container because it might not be running...


def ipv4_pool_add(cidr_pool):
    """
    Add the the given CIDR range to the IPv4 IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :return: None
    """
    try:
        pool = IPNetwork(cidr_pool)
    except AddrFormatError:
        print "%s is not a valid IPv4 prefix." % cidr_pool
        return
    if pool.version == 6:
        print "%s is an IPv6 prefix, this command is for IPv4." % cidr_pool
        return
    client = DatastoreClient()
    client.add_ip_pool("v4", pool)


def ipv4_pool_remove(cidr_pool):
    """
    Add the the given CIDR range to the IPv4 IP address allocation pool.

    :param cidr_pool: The pool to set in CIDR format, e.g. 192.168.0.0/16
    :return: None
    """

    try:
        pool = IPNetwork(cidr_pool)
    except AddrFormatError:
        print "%s is not a valid IPv4 prefix." % cidr_pool
        return
    if pool.version == 6:
        print "%s is an IPv6 prefix, this command is for IPv4." % cidr_pool
        return
    client = DatastoreClient()
    try:
        client.del_ip_pool("v4", pool)
    except KeyError:
        print "%s is not a configured pool." % cidr_pool


def ipv4_pool_show(version):
    """
    Print a list of IPv4 allocation pools.
    :return: None
    """
    client = DatastoreClient()
    pools = client.get_ip_pools(version)
    x = PrettyTable(["CIDR"])
    for pool in pools:
        x.add_row([pool])
    print x

def validate_arguments():
    group_ok = arguments["<GROUP>"] is None or re.match("^\w{1,30}$", arguments["<GROUP>"])
    ip_ok = arguments["--ip"] is None or netaddr.valid_ipv4(
        arguments["--ip"]) or netaddr.valid_ipv6(arguments["--ip"])
    container_ip_ok = arguments["<IP>"] is None or netaddr.valid_ipv4(
        arguments["<IP>"]) or netaddr.valid_ipv6(arguments["<IP>"])

    if not group_ok:
        print "Groups must be <30 character long and can only container numbers, letters and " \
              "underscore."
    if not ip_ok:
        print "Invalid ip argument"
    return group_ok and ip_ok and container_ip_ok


def create_dirs():
    mkdir_p("/var/log/calico")


def process_output(line):
    sys.stdout.write(line)


if __name__ == '__main__':
    arguments = docopt(__doc__)
    if os.geteuid() != 0:
        print "calicoctl must be run as root"
    elif validate_arguments():
        if arguments["master"]:
            if arguments["stop"]:
                master_stop(arguments["--force"])
            else:
                master(arguments["--ip"], arguments['--master-image'])
        elif arguments["node"]:
            if arguments["stop"]:
                node_stop(arguments["--force"])
            else:
                node_image = arguments['--node-image']
                ip6 = arguments["--ip6"]
                node(arguments["--ip"], node_image=node_image, ip6=ip6)
        elif arguments["status"]:
            status()
        elif arguments["reset"]:
            reset()
        elif arguments["group"]:
            if arguments["add"]:
                group_add(arguments["<GROUP>"])
            if arguments["remove"]:
                group_remove(arguments["<GROUP>"])
            if arguments["show"]:
                group_show(arguments["--detailed"])
            if arguments["addmember"]:
                group_add_container(arguments["<CONTAINER>"],
                                    arguments["<GROUP>"])
            if arguments["removemember"]:
                group_remove_container(arguments["<CONTAINER>"],
                                       arguments["<GROUP>"])
        elif arguments["diags"]:
            save_diags()
        elif arguments["shownodes"]:
            node_show(arguments["--detailed"])
        elif arguments["ipv4"]:
            assert arguments["pool"]
            if arguments["add"]:
                ipv4_pool_add(arguments["<CIDR>"])
            elif arguments["del"]:
                ipv4_pool_remove(arguments["<CIDR>"])
            elif arguments["show"]:
                ipv4_pool_show("v4")
        if arguments["container"]:
            if arguments["add"]:
                container_add(arguments["<CONTAINER>"], arguments["<IP>"])
            if arguments["remove"]:
                container_remove(arguments["<CONTAINER>"])
    else:
        print "Couldn't validate arguments. Exiting."
        exit(1)

