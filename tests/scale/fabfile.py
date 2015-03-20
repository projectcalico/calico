import random
from fabric.api import *
import re

"""
NOTE: This fabfile doesn't handle any of the "master" node interactions
The "master" node needs to run etcd and have the hostname "master" so the proxies can connect to it.
The master can be created with launch-master.sh

The compute nodes need to be named core<number>

Stage 0: Nothing exists
To move out of this stage some manual steps are required:
0) Ensure that you have gcloud, and you've authed and set a default project and zone.
1) create a new project on GCE (and update HOST_SUFFIX below)
2) Run a master node (using launch-master.sh)
3) Allow all traffic on the 192.168/16 network - also done by launch-master.sh

Stage 1: Compute hosts are running, routes are defined between them, calicoctl is present and calico-node is running.
To ensure that everything is cleaned up run the following before starting
    fab complete_reset reset_instances reset_routes

Then launch new instances, set up the routes
    fab create_instances create_routes download_calicoctl calicoctl_node

calico-node is now running and BGP sessions are established.


Stage 2: Workload containers are running.
Then create new workloads with
    fab create_workloads

You can now ping from al the workloads (to another random workload) using
    fab ping_from_all


To reset without starting over, run
    fab complete_reset download_calicoctl calicoctl_node

"""
#NOTE: Execute arbitrary commands with
# fab -- sudo ./calicoctl status

# Use the hosts generated with "gcloud compute config-ssh"
env.use_ssh_config = True

# Run the commands in parallel\
env.parallel = True

# Send SSH keepalives
env.keepalive = 5

HOST_PREFIX = "core"
HOST_SUFFIX = ".us-central1-c.nimble-ratio-866"
NUM_NODES = 6
NUM_WORKLOADS = 50

for node_number in xrange(1,NUM_NODES+1):
    env.hosts.append("%s%s%s" % (HOST_PREFIX, node_number, HOST_SUFFIX))

@task
@runs_once
def create_instances():
    """
    Create the compute nodes
    """
    hosts = ""
    for node_number in xrange(1,NUM_NODES+1):
        hosts+="%s%s " % (HOST_PREFIX, node_number)
    local("gcloud compute instances create %s "
          "--image https://www.googleapis.com/compute/v1/projects/coreos-cloud/global/images/coreos-alpha-618-0-0-v20150312 "
          "--machine-type g1-small "
          "--metadata-from-file user-data=cloud-config.yaml "
          "--can-ip-forward" % hosts)
    local("gcloud compute config-ssh")

@task
def complete_reset():
    """
    Wipe out all containers on teh host (except etcd) and redownload calicoctl
    """
    with settings(warn_only=True):
        run("rm calicoctl")
        run("docker rm -f $(docker ps -a | grep -v etcd | awk '{print $1}')")
        download_calicoctl()
        sudo("./calicoctl reset")

@task
@runs_once
def reset_routes():
    """
    Remove the gcloud routes
    """
    with settings(warn_only=True):
        local("gcloud compute routes list |grep ip- |awk '{print $1}' |xargs gcloud compute routes delete -q")

@task
@runs_once
def reset_instances():
    """
    Stop all gcloud instances
    """
    with settings(warn_only=True):
        local("gcloud compute instances list |grep core |awk '{print $1}' | xargs gcloud compute instances delete -q")

@task
def create_routes():
    """
    Create routes for each host
    """
    node_number = extract_host_number(env.host_string)
    sudo("bash -c 'echo 127.0.0.1 localhost >>/etc/hosts'")
    with settings(warn_only=True):
        #TODO Be careful with the zone here.
        local("gcloud compute routes create ip-192-168-%s-0 --next-hop-instance core%s --next-hop-instance-zone us-central1-c --destination-range 192.168.%s.0/24" % (node_number, node_number, node_number))
        sudo("ip addr add $(hostname -i) peer 10.240.0.1 dev ens4v1")
        sudo("ip route add unreachable 192.168.0.0/16")

@task
def download_calicoctl():
    """
    Download the calicoctl binary to each host
    """
    run("if [[ ! -e calicoctl ]]; then wget https://circle-artifacts.com/gh/Metaswitch/calico-docker/40/artifacts/0/home/ubuntu/calico-docker/dist/calicoctl;chmod +x calicoctl; fi")

@task
def calicoctl_node():
    """
    Run calicoctl node on each host
    """
    sudo("./calicoctl node --ip=$(hostname -i) --node-image=calico/node_testing:gevent")
    with settings(warn_only=True):
        sudo("./calicoctl group add DEFAULT")

class FabricException(Exception):
    pass

@task
def create_workloads():
    """
    Creates workload containers on each host
    """
    with settings(warn_only=True, command_timeout=5, abort_exception=FabricException):
        node_number = extract_host_number(env.host_string)
        for wl_num in xrange(1, NUM_WORKLOADS + 1):
            name = "wl_%s" % wl_num
            ip="192.168.%s.%s" % (node_number, wl_num)
            try:
                run("if ! docker ps |grep -w '%s'; then "
                    "DOCKER_HOST=localhost:2377 docker run -e CALICO_IP=%s --name %s -td busybox && "
                    "sudo ./calicoctl group addmember DEFAULT %s ;fi" % (name, ip, name, name))
            except FabricException:
                pass  # This is expected, we can continue.


# @task
# def destroy_workloads():
#     with settings(warn_only=True):
#         for wl_num in xrange(1, NUM_WORKLOADS + 1):
#             name = "wl_%s" % wl_num
#             sudo("./calicoctl container remove %s" % name)
#
#         run("docker rm -f $(docker ps -a | grep wl_ | awk '{print $1}')")

@task
def ping_from_all():
    """
    From each workload container, ping a random other container.
    Fail if any pings fail.
    """
    for wl_num in xrange(1, NUM_WORKLOADS + 1):
        name = "wl_%s" % wl_num

        random_ip = "192.168.%s.%s" % (random.randrange(1, NUM_NODES + 1),
                                       random.randrange(1, NUM_WORKLOADS + 1))
        run("docker exec %s ping -c 1 -W 1 %s" % (name, random_ip))

def extract_host_number(host_string):
    p = re.compile(".*?(\d+)")
    return p.match(host_string).group(1)