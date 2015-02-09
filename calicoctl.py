#!venv/bin/python
"""Calico..

Usage:
  calicoctl master --ip=<IP>
  calicoctl node --ip=<IP>
  calicoctl assignacl <CONTAINER_ID>
  calicoctl status
  calicoctl reset
  calicoctl version
  calicoctl addgroup <GROUP>
  calicoctl addtogroup <CONTAINER_ID> <GROUP>


Options:
 --ip=<IP>    The local management address to use.
"""
#Useful docker aliases
# alias docker_kill_all='sudo docker kill $(docker ps -q)'
# alias docker_rm_all='sudo docker rm -v `docker ps -a -q -f status=exited`'

from subprocess import call, check_output, CalledProcessError
import os
from docopt import docopt
from sh import mkdir
from sh import docker
from sh import modprobe
from sh import grep
import etcd
import sys
import socket
import json
import uuid
from collections import namedtuple

mkdir_p = mkdir.bake('-p')
hostname = socket.gethostname()

# etcd paths for Calico
HOST_PATH = "/calico/host/%(hostname)s/"
MASTER_IP_PATH = "/calico/master/ip"
GROUPS_PATH = "/calico/network/group/"
GROUP_PATH = "/calico/network/group/%(group_id)s/"
CONTAINER_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/"
ENDPOINTS_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/endpoint/"

POWERSTRIP_PORT = 2375


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

    def __init__(self):
        self.client = etcd.Client()

    def create_host(self, bird_ip):
        """
        Create a new Calico host.

        :param bird_ip: The IP address BIRD should listen on.
        :return: nothing.
        """
        host_path = HOST_PATH % {"hostname": hostname}
        # Set up the host
        self.client.write(host_path + "bird_ip", bird_ip)
        workload_dir = host_path + "workload"
        try:
            self.client.read(workload_dir)
        except KeyError:
            # Didn't exist, create it now.
            self.client.write(workload_dir, None, dir=True)
        return

    def set_master(self, ip):
        """
        Record the IP address of the Calico Master.
        :param ip: The IP address to reach Calico Master.
        :return: nothing.
        """
        # update the master IP
        self.client.write(MASTER_IP_PATH, ip)
        return

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
        self.client.write(group_path + "name", name)

        # Default rule
        self.client.write(group_path + "rule/inbound_default", "deny")
        self.client.write(group_path + "rule/outbound_default", "deny")

        # Allow traffic inbound from group.
        allow_group = Rule(group=group_id, cidr=None, protocol=None, port=None)
        self.client.write(group_path + "rule/inbound/1", allow_group.to_json())

        # Allow traffic outbound to group and any address.
        allow_any_ip = Rule(group=None, cidr="0.0.0.0/0", protocol=None, port=None)
        self.client.write(group_path + "rule/outbound/1", allow_group.to_json())
        self.client.write(group_path + "rule/outbound/2", allow_any_ip.to_json())

    def get_group_id(self, name):
        """
        Get the UUID of the named group.  If multiple groups have the same name, the first matching
        one will be returned.
        :param name:
        :return: string UUID for the group, or None if the name was not found.
        """
        groups = self.client.read(GROUPS_PATH, recursive=True,).children
        for child in groups:
            (_, _, _, _, group_id, final_key) = child.key.split("/", 5)
            if final_key == "name":
                if child.value == name:
                    return group_id
        return None

    def add_container_to_group(self, container_id, group_name):
        """
        Add a container (on this host) to the group with the given name.  This adds the first
        endpoint on the container to the group.

        :param container_id: The Docker container ID.
        :param group_name:  The Calico security group name.
        :return: None.
        """

        # Get the group UUID.
        group_id = self.get_group_id(group_name)
        if not group_id:
            raise KeyError("Group with name %s was not found." % group_name)

        # Get the endpoints from the container ID.
        ep_path = ENDPOINTS_PATH % {"hostname": hostname,
                                    "container_id": container_id}
        try:
            endpoints = self.client.read(ep_path).children
        except KeyError:
            # Re-raise with better message
            raise KeyError("Container with ID %s was not found." % container_id)

        # Get the first endpoint & ID
        endpoint = endpoints.next()
        (_, _, _, _, _, _, _, _, endpoint_id) = endpoint.key.split("/", 8)

        # Add the endpoint to the group.  ./member/ is a keyset of endpoint IDs, so write empty
        # string as the value.
        group_path = GROUP_PATH % {"group_id": group_id}
        self.client.write(group_path + "member/" + endpoint_id, "")


client = CalicoCmdLineEtcdClient()


def validate_arguments(arguments):
    # print(arguments)
    return True


def create_dirs():
    mkdir_p("/var/log/calico")
    mkdir_p("/tmp/config/data")


def process_output(line):
    sys.stdout.write(line)


def node(ip):
    create_dirs()
    modprobe("ip6_tables")
    modprobe("xt_set")

    # Set up etcd
    client.create_host(ip)

    cid = docker("run", "-e",  "IP=%s" % ip,
                 "--name=calico-node",
                 "--privileged",
                 "--net=host",  # BIRD/Felix can manipulate the base networking stack
                 "-v", "/var/run/docker.sock:/var/run/docker.sock",  # Powerstrip can access Docker
                 "-v", "/proc:/proc_host",  # Powerstrip Calico needs access to proc to set up
                                            # networking
                 "-d",
                 "calico/node")
    print "Calico node is running with id: %s" % cid
    print "Docker Remote API is on port %s.  Run \n" % POWERSTRIP_PORT
    print "export DOCKER_HOST=localhost:%s\n" % POWERSTRIP_PORT
    print "before using `docker run` for Calico networking.\n"


def master(ip):
    create_dirs()

    # Add IP to etcd
    client.set_master(ip)

    # Start the container
    cid = docker("run", "--name=calico-master",
                 "--privileged",
                 "--net=host",
                 "-d",
                 "calico/master")
    print "Calico master is running with id: %s" % cid

def status():
    try:
        print(grep(docker("ps"), "-i", "calico"))
    except Exception:
        print "No calico containers appear to be running"

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


def version():
    #TODO this won't work
    # print(docker("run", "--rm", "calico_felix", "apt-cache", "policy", "calico-felix"))
    print "Unknown"


def add_group(group_name):
    """
    Create a security group with the given name.
    :param group_name: The name for the group.
    :return: None.
    """

    # Check if the group exists.
    if client.get_group_id(group_name):
        print "Group %s already exists." % group_name
        return

    # Create the group.
    group_id = uuid.uuid1().hex
    client.create_group(group_id, group_name)
    print "Created group %s with ID %s" % (group_name, group_id)


def add_container_to_group(container_id, group_name):
    """
    Add the container to the listed group.
    :param container_id: ID of the container to add.
    :param group_name: Name of the group.
    :return: None
    """

    try:
        client.add_container_to_group(container_id, group_name)
    except KeyError as e:
        print e
    return

if __name__ == '__main__':
    if os.geteuid() != 0:
        print "calicoctl must be run as root"
    else:
        arguments = docopt(__doc__)
        if validate_arguments(arguments):
            if arguments["master"]:
                master(arguments["--ip"])
            if arguments["node"]:
                node(arguments["--ip"])
            if arguments["status"]:
                status()
            if arguments["reset"]:
                reset(arguments["--delete-images"])
            if arguments["version"]:
                version()
            if arguments["addgroup"]:
                add_group(arguments["<GROUP>"])
            if arguments["addtogroup"]:
                add_container_to_group(arguments["<CONTAINER_ID>"],
                                       arguments["<GROUP>"])
        else:
            print "Not yet"
