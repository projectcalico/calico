#!venv/bin/python
"""Calico..

Usage:
  calico master --ip=<IP>
  calico node
  calico assignacl <CONTAINER_ID>
  calico status
  calico reset [--delete-images]
  calico version


Options:
 --ip=<IP>    The address that other nodes can use to contact the master.
"""
#Useful docker aliases
# alias docker_kill_all='sudo docker kill $(docker ps -q)'
# alias docker_rm_all='sudo docker rm -v `docker ps -a -q -f status=exited`'

from subprocess import call, check_output, check_call, CalledProcessError
from string import Template
import socket
import os
from docopt import docopt
import shlex
import sh
from sh import mkdir
from sh import docker
from sh import modprobe
from sh import rm
import requests
import etcd
import sys

docker_run = docker.bake("run", "-d", "--net=none")
mkdir_p = mkdir.bake('-p')

HOSTNAME = socket.gethostname()
client = etcd.Client()

PLUGIN_TEMPLATE = Template("""[felix $name]
ip=$ip
host=$name

$peers
""")


def validate_arguments(arguments):
    # print(arguments)
    return True

def configure_master_components(peers):
    peer_config = ""

    for peer in peers:
        peer_config += "[felix {name}]\nip={address}\nhost={name}\n\n".format(name=peer,
                                                                         address=peer)

    # We need our name and address and name and address for all peers
    plugin_config = PLUGIN_TEMPLATE.substitute(ip=HOSTNAME, name=HOSTNAME, peers=peer_config)
    with open('config/data/felix.txt', 'w') as f:
        f.write(plugin_config)

    # ACL manager just need address of plugin manager
    aclmanager_config = ACL_TEMPLATE.substitute(ip=HOSTNAME)
    with open('config/acl_manager.cfg', 'w') as f:
        f.write(aclmanager_config)

def create_dirs():
    mkdir_p("config/data")
    mkdir_p("/var/log/calico")


def process_output(line):
    sys.stdout.write(line)

def launch(master, peers):
    create_dirs()
    modprobe("ip6_tables")
    modprobe("xt_set")

    # Assume that the image is already built - called calico_node
    docker("run", "-d", "calico/node")


def status():
    print(docker("ps"))

def reset(delete_images):
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


def master(peers):
    create_dirs()
    configure_master_components(peers)
    p = fig_master(l"up", "-d", _err=process_output, _out=process_output)
    p.wait()

if __name__ == '__main__':
    if os.geteuid() != 0:
        print "Calico must be run as root"
    else:
        arguments = docopt(__doc__)
        if validate_arguments(arguments):
            if arguments["master"]:
                master(arguments["--ip"])
            if arguments["node"]:
                launch()
            if arguments["status"]:
                status()
            if arguments["reset"]:
                reset(arguments["--delete-images"])
            if arguments["version"]:
                version()
        else:
            print "Not yet"
