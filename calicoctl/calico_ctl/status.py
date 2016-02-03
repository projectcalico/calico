# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
Usage:
  calicoctl status [--runtime=<RUNTIME>]

Description:
  Print current status information regarding calico-node container
  and the BIRD routing daemon.

Options:
  --runtime=<RUNTIME>       Specify the runtime used to run the calico/node 
                            container, either "docker" or "rkt". 
                            [default: docker]
"""
import re
import sys

import subprocess32
from prettytable import PrettyTable
from pycalico.datastore_errors import DataStoreError
from requests import ConnectionError
from subprocess32 import Popen, PIPE

from connectors import docker_client, client
from utils import hostname

# Extracts UUID, version and container status from rkt list output.
RKT_CONTAINER_RE = re.compile("([a-z0-9]+)\s+.*calico\/node:([a-z0-9\.\_\-]+)\s+([a-z]+)\s+")


def status(arguments):
    """
    Main dispatcher for status commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    # Check runtime.
    runtime = arguments.get("--runtime")
    if not runtime in ["docker", "rkt"]:
        print "Invalid runtime specified: '%s'" % runtime
        sys.exit(1)

    # Start by locating the calico-node container and querying the package
    # summary file.
    if runtime == "rkt":
        check_container_status_rkt()

        # Return - until rkt enter works for fly containers, we can't 
        # get BGP protocol information from within the node container.
        return 
    else:
        check_container_status_docker()

    # Now query the host BGP details.  If the AS number is not specified on the
    # host then it must be inheriting the default.
    try:
        bgp_ipv4, bgp_ipv6 = client.get_host_bgp_ips(hostname)
        bgp_as = client.get_host_as(hostname)
        if bgp_as is None:
            bgp_as = client.get_default_node_as()
            bgp_as += " (inherited)"
    except DataStoreError:
        print "Error connecting to etcd."
        bgp_ipv4 = bgp_ipv6 = "unknown"
        bgp_as = "unknown"

    # TODO: Add additional information to the BIRD section:
    # TODO: - Include AS numbers of peers
    # TODO: - Include host name of peers when the peer is a calico-node
    # TODO: - Include details of peers configured multiple times

    print "\nIPv4 BGP status"
    if bgp_ipv4:
        print "IP: %s    AS Number: %s" % (bgp_ipv4, bgp_as)
        pprint_bird_protocols(4)
    else:
        print "No IPv4 address configured.\n"

    print "IPv6 BGP status"
    if bgp_ipv6:
        print "IP: %s    AS Number: %s" % (bgp_ipv6, bgp_as)
        pprint_bird_protocols(6)
    else:
        print "No IPv6 address configured.\n"


def check_container_status_docker():
    """
    Checks and prints the calico/node container status when running in Docker. 
    """
    try:
        calico_node_info = filter(lambda container: "/calico-node" in
                                  container["Names"],
                                  docker_client.containers())
        if len(calico_node_info) == 0:
            print "calico-node container not running"
            sys.exit(1)
        else:
            print "calico-node container is running. Status: %s" % \
                  calico_node_info[0]["Status"]

            libraries_cmd = docker_client.exec_create("calico-node",
                                                      ["sh", "-c",
                                                       "cat libraries.txt"])
            libraries_out = docker_client.exec_start(libraries_cmd)
            result = re.search(r"^calico\s*\((.*)\)\s*$", libraries_out,
                               re.MULTILINE)

            if result is not None:
                print "Running felix version %s" % result.group(1)
    except ConnectionError:
        print "Docker is not running"
        sys.exit(1)


def check_container_status_rkt():
    """
    Checks and prints the calico/node container status when running in rkt. 
    """
    list_cmd = ["sudo", "rkt", "list"]
    p = Popen(list_cmd, stdin=PIPE, stdout=PIPE, stderr=PIPE)
    stdout, stderr = p.communicate()
    containers = RKT_CONTAINER_RE.findall(stdout) 

    if p.returncode:
        print "Unable to list rkt containers: '%s'" % stderr.strip()
        sys.exit(1)

    if len(containers) == 0:
        print "calico-node container not running"
        sys.exit(1)
    else:
        # Get statuses for all calico/node containers, and determine
        # if any are running.
        statuses = [c[2] for c in containers]
        running = "running" in statuses

        # If one is running, status is "running".  Else, use the status of
        # the first container.
        status = "running" if running else statuses[0]

        # Print status.  If it at least one is running, this will display
        # "running" status.
        print "calico-node container status: %s" % status


def pprint_bird_protocols(version):
    """
    Pretty print the output from the BIRD "show protocols".  This parses the
    existing output and lays it out in pretty printed table.

    :param version:  The IP version (4 or 6).
    :return: None.
    """
    # Based on the IP version, run the appropriate BIRD command, and select
    # the appropriate separator char for an IP address.
    if getattr(sys, 'frozen', False):
        # We're running under pyinstaller
        birdcl = sys._MEIPASS + "/birdcl"
    else:
        birdcl = "birdcl"
    try:
        if version == 4:
            results = subprocess32.check_output(
                   "echo show protocols | %s -s /var/run/calico/bird.ctl" % birdcl,
                   shell=True)
            ip_sep = "."
        else:
            results = subprocess32.check_output(
                  "echo show protocols | %s -s /var/run/calico/bird6.ctl" % birdcl,
                  shell=True)
            ip_sep = ":"
    except subprocess32.CalledProcessError:
        print "Couldn't connect to bird. Try running as root."
        return

    # Parse the output from BIRD to extract the values in the protocol status
    # table.  We'll further parse the name since that includes details about
    # the type of peer and the peer IP address.
    x = PrettyTable(["Peer address", "Peer type", "State",
                     "Since", "Info"])
    lines = results.split("\n")
    found_table = False
    for line in lines:
        # When BIRD displays its protocol table, it prints the bird> prompt and
        # then shifts the cursor to print back over the prompt.  However, this
        # means that we get rogue prompts when parsing the output.  For this
        # processing just remove the prompt if it is present.
        if line.startswith("bird>"):
            line = line[5:]

        # Skip blank lines.
        line = line.strip()
        if not line:
            continue

        # Split the line into columns based on whitespace separators.  We split
        # a maximum of 5 times because the 6th "info" column may contain a
        # string that itself includes whitespace that should be maintained.
        columns = re.split("\s+", line.strip(), 5)

        # Loop until we find the table heading.
        if columns == ["name", "proto", "table", "state", "since", "info"]:
            found_table = True
            continue
        elif not found_table:
            continue

        # We expect either 5 or 6 columns depending on whether there was a
        # value in the info column.  Anything else is not handled, so revert
        # to displaying the raw BIRD output.
        if not (5 <= len(columns) <= 6):
            found_table = False
            break

        # Parse the name, we name our BGP peers as "Mesh", "Node" or "Global"
        # followed by the IP address.  Extract the info so we can pretty
        # print it.
        combined = columns[0]
        if combined.startswith("Mesh_"):
            name = combined[5:].replace("_", ip_sep)
            ptype = "node-to-node mesh"
        elif combined.startswith("Node_"):
            name = combined[5:].replace("_", ip_sep)
            ptype = "node specific"
        elif combined.startswith("Global_"):
            name = combined[7:].replace("_", ip_sep)
            ptype = "global"
        else:
            # This is not a BGP Peer, so do not include in the output.
            continue

        x.add_row([name, ptype, columns[3], columns[4],
                   columns[5] if len(columns) == 6 else ""])

    # If we parsed the table then pretty print the table, otherwise just output
    # the BIRD output directly.  The first line of the BIRD output provides an
    # overall BIRD status.
    if found_table:
        print str(x) + "\n"
    else:
        print results + "\n"
