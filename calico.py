#!venv/bin/python
"""Calico..

Usage:
  calico master --ip=<IP>
  calico node --ip=<IP>
  calico assignacl <CONTAINER_ID>
  calico status
  calico reset
  calico version


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

mkdir_p = mkdir.bake('-p')

client = etcd.Client()

def validate_arguments(arguments):
    # print(arguments)
    return True

def create_dirs():
    mkdir_p("/var/log/calico")

def process_output(line):
    sys.stdout.write(line)

def node(ip):
    create_dirs()
    modprobe("ip6_tables")
    modprobe("xt_set")

    # --net=host required so BIRD/Felix can manipulate the base networking stack
    cid = docker("run", "-e",  "IP=%s" % ip, "--name=calico-node", "--privileged",
                                                                "--net=host", "-d", "calico/node")
    print "Calico node is running with id: %s" % cid

def master(ip):
    create_dirs()

    # update the master IP
    client.write('/calico/master/ip', ip)

    # Start the container
    cid = docker("run", "--name=calico-master", "--privileged", "--net=host", "-d",
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


if __name__ == '__main__':
    if os.geteuid() != 0:
        print "Calico must be run as root"
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
        else:
            print "Not yet"
