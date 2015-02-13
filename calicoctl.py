#!/usr/bin/env python
"""calicoctl

Usage:
  calicoctl master --ip=<IP>
                   [--etcd=<ETCD_AUTHORITY>]
                   [--master-image=<DOCKER_IMAGE_NAME>]
  calicoctl node --ip=<IP>
                 [--etcd=<ETCD_AUTHORITY>]
                 [--node-image=<DOCKER_IMAGE_NAME>]
  calicoctl status [--etcd=<ETCD_AUTHORITY>]
  calicoctl version [--etcd=<ETCD_AUTHORITY>]
  calicoctl shownodes [--detailed] [--etcd=<ETCD_AUTHORITY>]
  calicoctl group show [--detailed] [--etcd=<ETCD_AUTHORITY>]
  calicoctl group add <GROUP> [--etcd=<ETCD_AUTHORITY>]
  calicoctl group remove <GROUP> [--etcd=<ETCD_AUTHORITY>]
  calicoctl group addmember <GROUP> <CONTAINER> [--etcd=<ETCD_AUTHORITY>]
  calicoctl group removemember <GROUP> <CONTAINER> [--etcd=<ETCD_AUTHORITY>]
  calicoctl ipv4 pool add <CIDR> [--etcd=<ETCD_AUTHORITY>]
  calicoctl ipv4 pool del <CIDR> [--etcd=<ETCD_AUTHORITY>]
  calicoctl ipv4 pool show [--etcd=<ETCD_AUTHORITY>]
  calicoctl reset
  calicoctl diags

Options:
 --ip=<IP>                The local management address to use.
 --etcd=<ETCD_AUTHORITY>  The location of the etcd service as
                          host:port [default: 127.0.0.1:4001]
 --master-image=<DOCKER_IMAGE_NAME>  Docker image to use for
                          Calico's master container
                          [default: calico/master:v0.0.6]
 --node-image=<DOCKER_IMAGE_NAME>    Docker image to use for
                          Calico's per-node container
                          [default: calico/node:v0.0.6]

"""
from subprocess import call, check_output, CalledProcessError
import netaddr
import os
import re
from docopt import docopt
import etcd
import sys
import socket
import json
import uuid
from collections import namedtuple
import sh
import subprocess
import StringIO
import docker as pydocker
from netaddr import IPNetwork
from netaddr.core import AddrFormatError
from prettytable import PrettyTable

mkdir = sh.Command._create('mkdir')
docker = sh.Command._create('docker')
modprobe = sh.Command._create('modprobe')
grep = sh.Command._create('grep')

mkdir_p = mkdir.bake('-p')

hostname = socket.gethostname()

# etcd paths for Calico
HOST_PATH = "/calico/host/%(hostname)s/"
MASTER_IP_PATH = "/calico/master/ip"
GROUPS_PATH = "/calico/network/group/"
GROUP_PATH = "/calico/network/group/%(group_id)s/"
GROUP_MEMBER_PATH = "/calico/network/group/%(group_id)s/member"
CONTAINER_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/"
ENDPOINTS_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/endpoint/"
IP_POOL_PATH = "/calico/ipam/%(version)s/pool/"
IP_POOLS_PATH = "/calico/ipam/%(version)s/pool/"

POWERSTRIP_PORT = 2377

DEFAULT_IPV4_POOL = IPNetwork("192.168.0.0/16")

class Vividict(dict):
    # From http://stackoverflow.com/a/19829714
    def __missing__(self, key):
        value = self[key] = type(self)()
        return value

class Rule(namedtuple("Rule", ["group", "cidr", "protocol", "port"])):
    """
    A Calico inbound or outbound traffic rule.
    """

    def to_json(self):
        return json.dumps(self._asdict())


class CalicoCmdLineEtcdClient(object):
    """
    An etcd client that exposes high level Calico operations needed by the calico CLI.
    """

    def __init__(self, etcd_authority=None):
        if not etcd_authority:
            self.etcd_client = etcd.Client()
        else:
            # TODO: Error handling
            (host, port) = etcd_authority.split(":", 1)
            self.etcd_client = etcd.Client(host=host, port=int(port))

    def create_host(self, bird_ip):
        """
        Create a new Calico host.

        :param bird_ip: The IP address BIRD should listen on.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        # Set up the host
        self.etcd_client.write(host_path + "bird_ip", bird_ip)
        workload_dir = host_path + "workload"
        try:
            self.etcd_client.read(workload_dir)
        except KeyError:
            # Didn't exist, create it now.
            self.etcd_client.write(workload_dir, None, dir=True)
        return

    def set_master(self, ip):
        """
        Record the IP address of the Calico Master.
        :param ip: The IP address to reach Calico Master.
        :return: nothing.
        """
        # update the master IP
        self.etcd_client.write(MASTER_IP_PATH, ip)

    def get_master(self):
        """
        Get the IP address of the Calico Master
        :return: The IP address to reach Calico Master or None if it can't be found.
        """
        try:
            return self.etcd_client.get(MASTER_IP_PATH).value
        except KeyError:
            return None

    def get_ip_pools(self, version):
        """
        Get the configured IP pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: List of netaddr.IPNetwork IP pools.
        """
        assert version in ("v4", "v6")
        return self._get_ip_pools_with_keys(version).keys()

    def _get_ip_pools_with_keys(self, version):
        """
        Get configured IP pools with their etcd keys.

        :param version: "v4" for IPv4, "v6" for IPv6
        :return: dict of {<IPNetwork>: <etcd key>} for the pools.
        """
        pool_path = IP_POOLS_PATH % {"version": version}
        try:
            nodes = self.etcd_client.read(pool_path).children
        except KeyError:
            # Path doesn't exist.  Interpret as no configured pools.
            return {}
        else:
            pools = {}
            for child in nodes:
                cidr = child.value
                pool = IPNetwork(cidr)
                pools[pool] = child.key
            return pools

    def add_ip_pool(self, version, pool):
        """
        Add the given pool to the list of IP allocation pools.  If the pool already exists, this
        method completes silently without modifying the list of pools.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        # Normalize to CIDR format (i.e. 10.1.1.1/8 goes to 10.0.0.0/8)
        pool = pool.cidr

        # Check if the pool exists.
        if pool in self.get_ip_pools(version):
            return

        pool_path = IP_POOL_PATH % {"version": version}
        self.etcd_client.write(pool_path, str(pool), append=True)

    def del_ip_pool(self, version, pool):
        """
        Delete the given CIDR range from the list of pools.  If the pool does not exist, raise a
        KeyError.

        :param version: "v4" for IPv4, "v6" for IPv6
        :param pool: IPNetwork object representing the pool
        :return: None
        """
        assert version in ("v4", "v6")
        assert isinstance(pool, IPNetwork)

        pools = self._get_ip_pools_with_keys(version)
        try:
            key = pools[pool.cidr]
            self.etcd_client.delete(key)
        except KeyError:
            # Re-raise with a better error message.
            raise KeyError("%s is not a configured IP pool." % pool)

    def create_group(self, group_id, name):
        """
        Create a security group.  In this implementation, security groups accept traffic only from
        themselves, but can send traffic anywhere.

        :param group_id: Group UUID (string)
        :param name: Human readable name for the group.
        :return: nothing.
        """

        # Create the group directory.
        group_path = GROUP_PATH % {"group_id": group_id}
        self.etcd_client.write(group_path + "name", name)

        # Default rule
        self.etcd_client.write(group_path + "rule/inbound_default", "deny")
        self.etcd_client.write(group_path + "rule/outbound_default", "deny")

        # Allow traffic inbound from group.
        allow_group = Rule(group=group_id, cidr=None, protocol=None, port=None)
        self.etcd_client.write(group_path + "rule/inbound/1", allow_group.to_json())

        # Allow traffic outbound to group and any address.
        allow_any_ip = Rule(group=None, cidr="0.0.0.0/0", protocol=None, port=None)
        self.etcd_client.write(group_path + "rule/outbound/1", allow_group.to_json())
        self.etcd_client.write(group_path + "rule/outbound/2", allow_any_ip.to_json())

    def delete_group(self, name):
        """
        Delete a security group with a given name. If there are multiple groups with that name
        it will just delete one of them.

        :param name: Human readable name for the group.
        :return: the ID of the group that was deleted, or None if the group couldn't be found.
        """

        # Find a group ID
        group_id = self.get_group_id(name)
        if group_id:
            group_path = GROUP_PATH % {"group_id": group_id}
            self.etcd_client.delete(group_path, recursive=True, dir=True)
        return group_id

    def get_group_id(self, name_to_find):
        """
        Get the UUID of the named group.  If multiple groups have the same name, the first matching
        one will be returned.
        :param name_to_find:
        :return: string UUID for the group, or None if the name was not found.
        """
        for group_id, name in self.get_groups().iteritems():
            if name_to_find == name:
                return group_id
        return None

    def get_groups(self):
        """
        Get the all configured groups.
        :return: a dict of group_id => name
        """
        groups = {}
        try:
            etcd_groups = self.etcd_client.read(GROUPS_PATH, recursive=True,).leaves
            for child in etcd_groups:
                (_, _, _, _, group_id, final_key) = child.key.split("/", 5)
                if final_key == "name":
                    groups[group_id] = child.value
        except KeyError:
            # Means the GROUPS_PATH was not set up.  So, group does not exist.
            pass
        return groups

    def get_group_members(self, group_id):
        """
        Get the all configured groups.
        :return: a list of members
        """
        members = []
        try:
            etcd_members = self.etcd_client.read(GROUP_MEMBER_PATH % {"group_id": group_id},
                                                 recursive=True).leaves
            for child in etcd_members:
                id = child.key.split("/")[-1]
                if id != "member":
                    members.append(id)
        except KeyError:
            # Means the GROUPS_MEMBER_PATH was not set up.  So, group does not exist.
            pass
        print "%s : %s" % (group_id, members)
        return members

    def get_ep_id_from_cont(self, container_id):
        """
        Get a single endpoint ID from a container ID.

        :param container_id: The Docker container ID.
        :return: Endpoint ID as a string.
        """
        ep_path = ENDPOINTS_PATH % {"hostname": hostname,
                                    "container_id": container_id}
        try:
            endpoints = self.etcd_client.read(ep_path).leaves
        except KeyError:
            # Re-raise with better message
            raise KeyError("Container with ID %s was not found." % container_id)

        # Get the first endpoint & ID
        endpoint = endpoints.next()
        (_, _, _, _, _, _, _, _, endpoint_id) = endpoint.key.split("/", 8)
        return endpoint_id

    def get_hosts(self):
        """
        Get the all configured hosts
        :return: a dict of hostname => {type => {endpoint_id => {"addrs" => addr, "mac" => mac,
        "state" => state}}}
        """
        hosts = Vividict()
        try:
            etcd_hosts = self.etcd_client.read('/calico/host', recursive=True,).leaves
            for child in etcd_hosts:
                packed = child.key.split("/")
                if len(packed) != 10:
                    continue
                (_, _, _, host, _, type, container_id, _, endpoint_id, final_key) = packed
                hosts[host][type][container_id][endpoint_id][final_key] = child.value
        except KeyError as e:
            # Means the GROUPS_PATH was not set up.  So, group does not exist.
            pass

        return hosts


def parse_json(value):
    """
    Try to parse JSON out into a python data structure, so that when we serialize it back for
    zeroMQ we're not doing JSON in JSON.
    """
    ret_val = value
    try:
        ret_val = json.loads(value)
        log.debug("Parsed JSON %s", value)
    except ValueError:
        log.debug("Failed to parse JSON %s", value)

    return ret_val

class CalicoDockerClient(object):
    """
    A Docker client that exposes high level operations needed by Calico.
    """

    def __init__(self):
        self.docker_client = pydocker.Client(base_url='unix://var/run/docker.sock')

    def get_container_id(self, container_name):
        """
        Get the full container ID from a partial ID or name.

        :param container_name: The partial ID or name of the container.
        :return: The container ID as a string.
        """

        info = self.docker_client.inspect_container(container_name)
        return info["Id"]


class CalicoDockerEtcd(CalicoDockerClient, CalicoCmdLineEtcdClient):
    """
    A client that interacts with both Docker and etcd to provide high-level Calico abstractions.
    """

    def __init__(self, etcd_authority=None):
        CalicoCmdLineEtcdClient.__init__(self, etcd_authority)
        CalicoDockerClient.__init__(self)

    def add_container_to_group(self, container_name, group_name):
        """
        Add a container (on this host) to the group with the given name.  This adds the first
        endpoint on the container to the group.

        :param container_name: The Docker container name or ID.
        :param group_name:  The Calico security group name.
        :return: None.
        """

        # Resolve the name to ID.
        try:
            container_id = self.get_container_id(container_name)
        except pydocker.errors.APIError as e:
            if e.response.status_code == 404:
                # Re-raise as a key error for consistency.
                raise KeyError("Container %s was not found." % container_name)
            else:
                raise

        # Get the group UUID.
        group_id = self.get_group_id(group_name)
        if not group_id:
            raise KeyError("Group with name %s was not found." % group_name)

        endpoint_id = self.get_ep_id_from_cont(container_id)

        # Add the endpoint to the group.  ./member/ is a keyset of endpoint IDs, so write empty
        # string as the value.
        group_path = GROUP_PATH % {"group_id": group_id}
        self.etcd_client.write(group_path + "member/" + endpoint_id, "")

    def remove_container_from_group(self, container_name, group_name):
        """
        Add a container (on this host) to the group with the given name.  This adds the first
        endpoint on the container to the group.

        :param container_name: The Docker container name or ID.
        :param group_name:  The Calico security group name.
        :return: None.
        """

        # Resolve the name to ID.
        try:
            container_id = self.get_container_id(container_name)
        except pydocker.errors.APIError as e:
            if e.response.status_code == 404:
                # Re-raise as a key error for consistency.
                raise KeyError("Container %s was not found." % container_name)
            else:
                raise

        # Get the group UUID.
        group_id = self.get_group_id(group_name)
        if not group_id:
            raise KeyError("Group with name %s was not found." % group_name)

        endpoint_id = self.get_ep_id_from_cont(container_id)

        # Remove the endpoint from the group.
        group_path = GROUP_PATH % {"group_id": group_id}
        self.etcd_client.delete(group_path + "member/" + endpoint_id)




def create_dirs():
    mkdir_p("/var/log/calico")


def process_output(line):
    sys.stdout.write(line)


def node(ip, node_image):
    create_dirs()
    modprobe("ip6_tables")
    modprobe("xt_set")

    # Set up etcd
    client = CalicoCmdLineEtcdClient(etcd_authority)

    master_ip = client.get_master()
    if not master_ip:
        print "No master can be found. Exiting"
        return

    ipv4_pools = client.get_ip_pools("v4")
    if not ipv4_pools:
        print "No IPv4 range defined.  Exiting."
        return

    print "Using master on IP: %s" % master_ip
    client.create_host(ip)
    try:
        docker("rm", "-f", "calico-node")
    except Exception:
        pass

    output = StringIO.StringIO()

    docker("run", "-e",  "IP=%s" % ip,
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
    print "Calico node is running with id: %s" % cid
    print "Docker Remote API is on port %s.  Run \n" % POWERSTRIP_PORT
    print "export DOCKER_HOST=localhost:%s\n" % POWERSTRIP_PORT
    print "before using `docker run` for Calico networking.\n"


def master(ip, master_image):
    create_dirs()

    # Add IP to etcd
    client = CalicoCmdLineEtcdClient(etcd_authority)
    client.set_master(ip)

    # If no IPv4 pools are defined, add a default.
    ipv4_pools = client.get_ip_pools("v4")
    if len(ipv4_pools) == 0:
        client.add_ip_pool("v4", DEFAULT_IPV4_POOL)

    try:
        docker("rm", "-f", "calico-master")
    except Exception:
        pass

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
    client = CalicoCmdLineEtcdClient(etcd_authority)
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
        pass
    except Exception:
        print "Couldn't collect BGP Peer information"

    print(docker("exec", "calico-node", "/bin/bash",  "-c", "echo show protocols | birdc -s "
                                                                "/etc/service/bird/bird.ctl"))


def reset():
    try:
        interfaces_raw = check_output("ip link show | grep -Eo ' (tap(.*?)):' |grep -Eo '[^ :]+'", shell=True)
        print "Removing interfaces:\n%s" % interfaces_raw
        interfaces = interfaces_raw.splitlines()
        for interface in interfaces:
            call("ip link delete %s" % interface, shell=True)
    except CalledProcessError:
        print "No interfaces to clean up"


def add_group(group_name):
    """
    Create a security group with the given name.
    :param group_name: The name for the group.
    :return: None.
    """
    client = CalicoCmdLineEtcdClient(etcd_authority)
    # Check if the group exists.
    if client.get_group_id(group_name):
        print "Group %s already exists." % group_name
        return

    # Create the group.
    group_id = uuid.uuid1().hex
    client.create_group(group_id, group_name)
    print "Created group %s with ID %s" % (group_name, group_id)


def add_container_to_group(container_name, group_name):
    """
    Add the container to the listed group.
    :param container_name: ID of the container to add.
    :param group_name: Name of the group.
    :return: None
    """
    client = CalicoDockerEtcd(etcd_authority)
    try:
        client.add_container_to_group(container_name, group_name)
        print "Added container %s to %s" % (container_name, group_name)
    except KeyError as e:
        print str(e)

def remove_container_from_group(container_name, group_name):
    """
    Remove the container from the listed group.
    :param container_name: ID of the container to remove.
    :param group_name: Name of the group.
    :return: None
    """
    client = CalicoDockerEtcd(etcd_authority)
    try:
        client.remove_container_from_group(container_name, group_name)
        print "Removed container %s from %s" % (container_name, group_name)
    except KeyError as e:
        print str(e)

def remove_group(group_name):
    #TODO - Don't allow removing a group that has enpoints in it.
    client = CalicoCmdLineEtcdClient(etcd_authority)
    group_id = client.delete_group(group_name)
    if group_id:
        print "Deleted group %s with ID %s" % (group_name, group_id)
    else:
        print "Couldn't find group with name %s" % group_name


def show_groups(detailed):
    client = CalicoCmdLineEtcdClient(etcd_authority)
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

def show_nodes(detailed):
    client = CalicoCmdLineEtcdClient(etcd_authority)
    hosts = client.get_hosts()

    if detailed:
        x = PrettyTable(["Host", "Workload Type", "Workload ID", "Endpoint ID", "Addresses",
                         "MAC", "State"])
        for host, types in hosts.iteritems():
            for type, workloads in types.iteritems():
                for workload, endpoints in workloads.iteritems():
                    for endpoint, data in endpoints.iteritems():
                        x.add_row([host, type, workload, endpoint, data["addrs"], data["mac"],
                                   data["state"]])
    else:
        x = PrettyTable(["Host", "Workload Type", "Number of workloads"])
        for host, types in hosts.iteritems():
            for type, workloads in types.iteritems():
              x.add_row([host, type, len(workloads)])

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

echo "Uploading file. It will be available for 14 days from the following URL (printed when the upload completes)"
curl --upload-file $FILENAME https://transfer.sh/$FILENAME

popd >/dev/null

echo "Done"
"""
    bash = sh.Command._create('bash')
    bash(_in=script, _err=process_output, _out=process_output).wait()
    # # Pipe the diags script to bash
    # # TODO: reimplement this in Python
    # proc = subprocess.Popen("bash",
    #                         stdin=subprocess.PIPE,
    #                         stdout=subprocess.PIPE,
    #                         stderr=subprocess.STDOUT,
    #                         bufsize=1)
    #
    # for line in iter(proc.stdout.readline, b''):
    #     print line,
    # proc.communicate()
    # # (out, _) = proc.communicate(script)
    # # print out #TODO - Make this stream the output

def ipv4_pool(dc_args):
    """
    Dispatch "ipv4 pool" commands
    :param dc_args: docopt arguments structure.
    :return: None.
    """
    if dc_args["add"]:
        add_ipv4_pool(dc_args["<CIDR>"])
    elif dc_args["del"]:
        del_ipv4_pool(dc_args["<CIDR>"])
    elif dc_args["show"]:
        show_ip_pools("v4")


def add_ipv4_pool(cidr_pool):
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
    client = CalicoCmdLineEtcdClient(etcd_authority)
    client.add_ip_pool("v4", pool)


def del_ipv4_pool(cidr_pool):
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
    client = CalicoCmdLineEtcdClient(etcd_authority)
    try:
        client.del_ip_pool("v4", pool)
    except KeyError:
        print "%s is not a configured pool." % cidr_pool


def show_ip_pools(version):
    """
    Print a list of IPv4 allocation pools.
    :return: None
    """
    client = CalicoCmdLineEtcdClient(etcd_authority)
    pools = client.get_ip_pools(version)
    for pool in pools:
        print pool

def validate_arguments(arguments):
    group_ok = arguments["<GROUP>"] is None or re.match("^\w{1,30}$", arguments["<GROUP>"])
    ip_ok = arguments["--ip"] is None or netaddr.valid_ipv4(arguments["--ip"]) or \
                                         netaddr.valid_ipv6(arguments["--ip"])
    if not group_ok:
        print "Groups must be <30 character longs and can only container numbers, letters and " \
              "underscore."
    if not ip_ok:
        print "Invalid --ip argument"
    # TODO
    # --container
    # --etcd
    return ip_ok and group_ok

if __name__ == '__main__':
    arguments = docopt(__doc__)
    etcd_authority = arguments["--etcd"]
    if os.geteuid() != 0:
        print "calicoctl must be run as root"
    elif validate_arguments(arguments):
        if arguments["master"]:
            master_image = arguments['--master-image']
            master(arguments["--ip"], master_image=master_image)
        elif arguments["node"]:
            node_image = arguments['--node-image']
            node(arguments["--ip"], node_image=node_image)
        elif arguments["status"]:
            status()
        elif arguments["reset"]:
            reset()
        elif arguments["group"]:
            if arguments["add"]:
                add_group(arguments["<GROUP>"])
            if arguments["remove"]:
                remove_group(arguments["<GROUP>"])
            if arguments["show"]:
                show_groups(arguments["--detailed"])
            if arguments["addmember"]:
                add_container_to_group(arguments["<CONTAINER>"],
                                       arguments["<GROUP>"])
            if arguments["removemember"]:
                remove_container_from_group(arguments["<CONTAINER>"],
                                            arguments["<GROUP>"])
        elif arguments["diags"]:
            save_diags()
        elif arguments["shownodes"]:
            show_nodes(arguments["--detailed"])
        elif arguments["ipv4"]:
            assert arguments["pool"]
            ipv4_pool(arguments)