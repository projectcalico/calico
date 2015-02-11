#!venv/bin/python
"""Calico..

Usage:
  calicoctl master --ip=<IP> [--etcd=<ETCD_AUTHORITY>]
  calicoctl node --ip=<IP> [--etcd=<ETCD_AUTHORITY>]
  calicoctl status
  calicoctl reset
  calicoctl version
  calicoctl addgroup <GROUP>  [--etcd=<ETCD_AUTHORITY>]
  calicoctl addtogroup <CONTAINER_ID> <GROUP>  [--etcd=<ETCD_AUTHORITY>]
  calicoctl diags
  calicoctl showgroups [--etcd=<ETCD_AUTHORITY>]
  calicoctl removegroup <GROUP> [--etcd=<ETCD_AUTHORITY>]


Options:
 --ip=<IP>                  The local management address to use.
 --etcd=<ETCD_AUTHORITY>    The location of the etcd service as host:port [default: 127.0.0.1:4001]

"""
#Useful docker aliases
# alias docker_kill_all='sudo docker kill $(docker ps -q)'
# alias docker_rm_all='sudo docker rm -v `docker ps -a -q -f status=exited`'

from subprocess import call, check_output, CalledProcessError
import os
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
CONTAINER_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/"
ENDPOINTS_PATH = "/calico/host/%(hostname)s/workload/docker/%(container_id)s/endpoint/"

POWERSTRIP_PORT = 2377


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
        :param name:
        :return: string UUID for the group, or None if the name was not found.
        """
        for id, name in self.get_groups().iteritems():
            if name_to_find == name:
                return id
        return None

    def get_groups(self):
        """
        Get the all configured groups.
        :return: a dict of group_id => name
        """
        groups = {}
        try:
            etcd_groups = self.etcd_client.read(GROUPS_PATH, recursive=True,).children
            for child in etcd_groups:
                (_, _, _, _, group_id, final_key) = child.key.split("/", 5)
                if final_key == "name":
                    groups[group_id] = child.value
        except KeyError as e:
            # Means the GROUPS_PATH was not set up.  So, group does not exist.
            pass
        return groups

    def get_ep_id_from_cont(self, container_id):
        """
        Get a single endpoint ID from a container ID.

        :param container_id: The Docker container ID.
        :return: Endpoint ID as a string.
        """
        ep_path = ENDPOINTS_PATH % {"hostname": hostname,
                                    "container_id": container_id}
        try:
            endpoints = self.etcd_client.read(ep_path).children
        except KeyError:
            # Re-raise with better message
            raise KeyError("Container with ID %s was not found." % container_id)

        # Get the first endpoint & ID
        endpoint = endpoints.next()
        (_, _, _, _, _, _, _, _, endpoint_id) = endpoint.key.split("/", 8)
        return endpoint_id


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


def validate_arguments(arguments):
    # print(arguments)
    return True


def create_dirs():
    mkdir_p("/var/log/calico")


def process_output(line):
    sys.stdout.write(line)


def node(ip, etcd_authority):
    create_dirs()
    modprobe("ip6_tables")
    modprobe("xt_set")

    # Set up etcd
    client = CalicoCmdLineEtcdClient(etcd_authority)

    master_ip = client.get_master()

    if not master_ip:
        print "No master can be found. Exiting"
    else:
        print "Using master on IP: %s" % master_ip
        client.create_host(ip)
        try:
            docker("rm", "-f", "calico-node")
        except Exception:
            pass

        output = StringIO.StringIO()

        docker("run", "-e",  "IP=%s" % ip,
                     "--name=calico-node",
                     "--privileged",
                     "--net=host",  # BIRD/Felix can manipulate the base networking stack
                     "-v", "/var/run/docker.sock:/var/run/docker.sock",  # Powerstrip can access Docker
                     "-v", "/proc:/proc_host",  # Powerstrip Calico needs access to proc to set up
                                                # networking
                     "-v", "/var/log/calico:/var/log/calico",  # Logging volume
                     "-e", "ETCD_AUTHORITY=%s" % etcd_authority,  # etcd host:port
                     "-d",
                     "calico/node", _err=process_output, _out=output).wait()

        cid = output.getvalue().strip()
        output.close()
        print "Calico node is running with id: %s" % cid
        print "Docker Remote API is on port %s.  Run \n" % POWERSTRIP_PORT
        print "export DOCKER_HOST=localhost:%s\n" % POWERSTRIP_PORT
        print "before using `docker run` for Calico networking.\n"


def master(ip, etcd_authority):
    create_dirs()

    # Add IP to etcd
    client = CalicoCmdLineEtcdClient(etcd_authority)
    client.set_master(ip)
    try:
        docker("rm", "-f", "calico-master")
    except Exception:
        pass

    output = StringIO.StringIO()
    
    # Start the container
    docker("run", "--name=calico-master",
                 "--privileged",
                 "--net=host",
                 "-v", "/var/log/calico:/var/log/calico",  # Logging volume
                 "-e", "ETCD_AUTHORITY=%s" % etcd_authority,  # etcd host:port
                 "-d",
                 "calico/master", _err=process_output, _out=output).wait()
    cid = output.getvalue().strip()
    output.close()
    print "Calico master is running with id: %s" % cid

def status():
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


def add_group(group_name, etcd_authority):
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


def add_container_to_group(container_name, group_name, etcd_authority):
    """
    Add the container to the listed group.
    :param container_name: ID of the container to add.
    :param group_name: Name of the group.
    :return: None
    """
    client = CalicoDockerEtcd(etcd_authority)
    try:
        client.add_container_to_group(container_name, group_name)
    except KeyError as e:
        print e
    return

def remove_group(group_name, etcd_authority):
    #TODO - Don't allow removing a group that has enpoints in it.
    client = CalicoDockerEtcd(etcd_authority)
    group_id = client.delete_group(group_name)
    if group_id:
        print "Deleted group %s with ID %s" % (group_name, group_id)
    else:
        print "Couldn't find group with name %s" % group_name


def show_groups(etcd_authority):
    client = CalicoDockerEtcd(etcd_authority)

    from prettytable import PrettyTable
    x = PrettyTable(["ID", "Name"])
    for group_id, name in client.get_groups().iteritems():
        x.add_row([group_id, name])

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
diags_dir="/tmp/$date"
system=`hostname`
echo $diags_dir
mkdir $diags_dir
pushd $diags_dir

echo DATE=$date > date
echo $system > hostname

for cmd in "route -n" "ip route" "ip -6 route"
do
  echo $cmd >> $ROUTE_FILE
  $cmd >> $ROUTE_FILE
  echo >> $ROUTE_FILE
done
netstat -an > netstat

iptables -v -L > $IPTABLES_PREFIX
iptables -v -L -t nat > $IPTABLES_PREFIX-nat
iptables -v -L -t mangle > $IPTABLES_PREFIX-mangle
iptables -v -L > $IP6TABLES_PREFIX
iptables -v -L -t nat > $IP6TABLES_PREFIX-nat
iptables -v -L -t mangle > $IP6TABLES_PREFIX-mangle
ipset list > ipset

cp -a $CALICO_DIR .
curl -s -L http://127.0.0.1:4001/v2/keys/calico?recursive=true -o etcd_calico

mkdir logs
cp /var/log/*log logs

tar -zcf $diags_dir.gz *

popd

echo "Diags saved to $diags_dir.gz"
"""
    # Pipe the diags script to bash
    # TODO: reimplement this in Python
    proc = subprocess.Popen("bash",
                            stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    (out, _) = proc.communicate(script)
    print out #TODO - Make this stream the output


if __name__ == '__main__':
    arguments = docopt(__doc__)
    if os.geteuid() != 0:
        print "calicoctl must be run as root"
    elif validate_arguments(arguments):
        if arguments["master"]:
            master(arguments["--ip"], arguments["--etcd"])
        if arguments["node"]:
            node(arguments["--ip"], arguments["--etcd"])
        if arguments["status"]:
            status()
        if arguments["reset"]:
            reset(arguments["--delete-images"])
        if arguments["addgroup"]:
            add_group(arguments["<GROUP>"], arguments["--etcd"])
        if arguments["removegroup"]:
            remove_group(arguments["<GROUP>"], arguments["--etcd"])
        if arguments["showgroups"]:
            show_groups(arguments["--etcd"])
        if arguments["addtogroup"]:
            add_container_to_group(arguments["<CONTAINER_ID>"],
                                   arguments["<GROUP>"],
                                   arguments["--etcd"])
        if arguments["diags"]:
            save_diags()
    else:
        print "Not yet"
