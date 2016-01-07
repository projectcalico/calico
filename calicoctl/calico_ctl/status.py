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
  calicoctl status

Description:
  Print current status information regarding calico-node container
  and the BIRD routing daemon.
"""
import re
import sys

from prettytable import PrettyTable
from requests import ConnectionError

from connectors import docker_client, client
from utils import hostname

from pycalico.datastore_errors import DataStoreError

def status(arguments):
    """
    Main dispatcher for status commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    # Start by locating the calico-node container and querying the package
    # summary file.
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
        # TODO: Perform status checks in platform-independent way.
        sys.exit(1)

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


def pprint_bird_protocols(version):
    """
    Pretty print the output from the BIRD "show protocols".  This parses the
    existing output and lays it out in pretty printed table.

    :param version:  The IP version (4 or 6).
    :return: None.
    """
    # Based on the IP version, run the appropriate BIRD command, and select
    # the appropriate separator char for an IP address.
    if version == 4:
        bird_cmd = docker_client.exec_create("calico-node",
                                    ["sh", "-c",
                                     "echo show protocols | "
                                     "birdcl -s /etc/service/bird/bird.ctl"])
        results = docker_client.exec_start(bird_cmd)
        ip_sep = "."
    else:
        bird6_cmd = docker_client.exec_create("calico-node",
                                    ["sh", "-c",
                                     "echo show protocols | "
                                     "birdcl -s "
                                     "/etc/service/bird6/bird6.ctl"])
        results = docker_client.exec_start(bird6_cmd)
        ip_sep = ":"

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
