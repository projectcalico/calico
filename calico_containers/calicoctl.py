#!/usr/bin/env python

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

"""calicoctl

Override the host:port of the ETCD server by setting the environment variable
ETCD_AUTHORITY [default: 127.0.0.1:4001]

Usage: calicoctl <command> [<args>...]

    status            Print current status information
    node              Configure the main calico/node container and establish Calico networking
    container         Configure containers and their addresses
    profile           Configure endpoint profiles
    endpoint          Configure the endpoints assigned to existing containers
    pool              Configure ip-pools
    bgp               Configure global bgp
    checksystem       Check for incompatabilities on the host system
    diags             Save diagnostic information

See 'calicoctl <command> --help' to read about a specific subcommand.
"""
import sys
import traceback
import netaddr
from netaddr import AddrFormatError
import re
from docopt import docopt
from pycalico.datastore_errors import DataStoreError

import calico_ctl.node
import calico_ctl.container
import calico_ctl.profile
import calico_ctl.endpoint
import calico_ctl.pool
import calico_ctl.bgp
import calico_ctl.checksystem
import calico_ctl.status
import calico_ctl.diags
from calico_ctl.utils import print_paragraph


def validate_arguments(arguments):
        """
        Validate common argument values.

        :param arguments: Docopt processed arguments.
        """
        # List of valid characters that Felix permits
        valid_chars = '[a-zA-Z0-9_\.\-]'

        # Validate Profiles
        profile_ok = True
        if "<PROFILES>" in arguments or "<PROFILE>" in arguments:
            profiles = arguments.get("<PROFILES>") or arguments.get("<PROFILE>")
            if profiles:
                for profile in profiles:
                    if not re.match("^%s+$" % valid_chars, profile):
                        profile_ok = False
                        break

        # Validate tags
        tag_ok = (arguments.get("<TAG>") is None or
                  re.match("^%s+$" % valid_chars, arguments["<TAG>"]))

        # Validate IPs
        ip_ok = arguments.get("--ip") is None or netaddr.valid_ipv4(arguments.get("--ip"))
        ip6_ok = arguments.get("--ip6") is None or \
                 netaddr.valid_ipv6(arguments.get("--ip6"))
        container_ip_ok = arguments.get("<IP>") is None or \
                          netaddr.valid_ipv4(arguments["<IP>"]) or \
                          netaddr.valid_ipv6(arguments["<IP>"])
        peer_ip_ok = arguments.get("<PEER_IP>") is None or \
                     netaddr.valid_ipv4(arguments["<PEER_IP>"]) or \
                     netaddr.valid_ipv6(arguments["<PEER_IP>"])
        cidr_ok = True
        for arg in ["<CIDR>", "<SRCCIDR>", "<DSTCIDR>"]:
            if arguments.get(arg):
                try:
                    arguments[arg] = str(netaddr.IPNetwork(arguments[arg]))
                except (AddrFormatError, ValueError):
                    # Some versions of Netaddr have a bug causing them to return a
                    # ValueError rather than an AddrFormatError, so catch both.
                    cidr_ok = False
        icmp_ok = True
        for arg in ["<ICMPCODE>", "<ICMPTYPE>"]:
            if arguments.get(arg) is not None:
                try:
                    value = int(arguments[arg])
                    if not (0 <= value < 255):  # Felix doesn't support 255
                        raise ValueError("Invalid %s: %s" % (arg, value))
                except ValueError:
                    icmp_ok = False
        asnum_ok = True
        if arguments.get("<AS_NUM>") or arguments.get("--as"):
            try:
                asnum = int(arguments["<AS_NUM>"] or arguments["--as"])
                asnum_ok = 0 <= asnum <= 4294967295
            except ValueError:
                asnum_ok = False

        detach_ok = True
        if arguments.get("<DETACH>") or arguments.get("--detach"):
            detach_ok = arguments.get("--detach") in ["true", "false"]

        if not profile_ok:
            print_paragraph("Profile names must be < 40 character long and can "
                            "only contain numbers, letters, dots, dashes and "
                            "underscores.")
        if not tag_ok:
            print_paragraph("Tags names can only contain numbers, letters, dots, "
                            "dashes and underscores.")
        if not ip_ok:
            print "Invalid IPv4 address specified with --ip argument."
        if not ip6_ok:
            print "Invalid IPv6 address specified with --ip6 argument."
        if not container_ip_ok or not peer_ip_ok:
            print "Invalid IP address specified."
        if not cidr_ok:
            print "Invalid CIDR specified."
        if not icmp_ok:
            print "Invalid ICMP type or code specified."
        if not asnum_ok:
            print "Invalid AS Number specified."
        if not detach_ok:
            print "Valid values for --detach are 'true' and 'false'"

        if not (profile_ok and ip_ok and ip6_ok and tag_ok and peer_ip_ok and
                container_ip_ok and cidr_ok and icmp_ok and asnum_ok and
                detach_ok):
            sys.exit(1)


if __name__ == '__main__':
    """
    Calicoctl interprets the first sys.argv (after the file name) as a submodule.
    Calicoctl works on the assumption that each subcommand will have a python
    file sharing its name in the calico_ctl/ directory. This file should
    also have a function sharing that same name which accepts a single
    argument - a docopt processed input dictionary.

    Example:
      calico_ctl/node.py has a function called node(arguments)
    """
    # If no arguments were provided in the function call, add the help flag
    # to trigger the main help message
    if len(sys.argv) == 1:
        docopt(__doc__, options_first=True, argv=['--help'])
        exit(1)

    # Run command through initial docopt processing to determine subcommand
    command_args = docopt(__doc__, options_first=True)

    # Group the additional args together and forward them along
    argv = [command_args['<command>']] + command_args['<args>']

    # Dispatch the appropriate subcommand
    try:
        command = command_args['<command>']

        # Look for a python file in the calico_ctl module which
        # shares the same name as the input command
        command_module = getattr(calico_ctl, command)

        # docopt the arguments through that module's docstring
        arguments = docopt(command_module.__doc__, argv=argv)
        validate_arguments(arguments)

        # Call the dispatch function in that module which should also have
        # the same name
        getattr(command_module, command)(arguments)
    except AttributeError:
        # Unrecognized submodule. Show main help message
        docopt(__doc__, options_first=True, argv=['--help'])
    except SystemExit:
        raise
    except DataStoreError as e:
        print_paragraph(e.message)
        sys.exit(1)
    except BaseException as e:
        print "Unexpected error executing command.\n"
        traceback.print_exc()
        sys.exit(1)
