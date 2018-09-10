import json
import netaddr
import os
import random
import string
from subprocess import check_call, check_output, CalledProcessError

import sys

NETNS_ROOT = "/var/run/netns/"
import os
PLUGIN_LOCATION = os.path.dirname(os.path.realpath(__file__)) + "/../../bin/amd64/"
def create_container(extra_suffix=""):
    # Generate a random container_id
    container_id = ''.join(random.choice(string.ascii_lowercase + string.digits) for _ in range(10))
    netnspath = NETNS_ROOT + container_id
    check_call("ip netns add " + container_id, shell=True)
    check_call("ip netns exec %s ip link set lo up " % container_id, shell=True)


    # Set the required env vars to call the CNI plugin
    os.environ.update({"CNI_COMMAND": "ADD",
                       "CNI_CONTAINERID": container_id,
                       "CNI_NETNS": netnspath,
                       "CNI_IFNAME": "eth0",
                       "CNI_PATH": PLUGIN_LOCATION})

    # Find the plugin to call from the json
    plugin = ""
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
        plugin = PLUGIN_LOCATION + data["type"]

    # Open the file again to pass the file handle as the stdin to call the plugin
    with open(sys.argv[1], 'r') as f:
        try:
            output = check_output(extra_suffix+plugin, stdin=f, env=os.environ, shell=True)
            print output
            ip = json.loads(output)["ips"][0]["address"]
        except CalledProcessError as e:
            print "Plugin call failed"
            print e.output
            sys.exit(e.returncode)

    return (container_id, netaddr.IPNetwork(ip).ip)

def delete_container(container_id, extra_suffix=""):
    netnspath = NETNS_ROOT + container_id
    os.environ.update({"CNI_COMMAND": "DEL",
                       "CNI_CONTAINERID": container_id,
                       "CNI_NETNS": netnspath,
                       "CNI_IFNAME": "eth0",
                       "CNI_PATH": PLUGIN_LOCATION})
    os.environ["CNI_COMMAND"] = "DEL"
    with open(sys.argv[1], 'r') as f:
        data = json.load(f)
        plugin = PLUGIN_LOCATION + data["type"]

    with open(sys.argv[1], 'r') as f:
        check_call(extra_suffix + plugin, stdin=f, env=os.environ, shell=True)
    check_call("ip netns delete %s" % container_id, shell=True)

def run_command(container_id, command):
    check_call("ip netns exec %s %s" % (container_id, command), shell=True)
