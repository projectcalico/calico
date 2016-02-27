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
  calicoctl profile show [--detailed]
  calicoctl profile add <PROFILE>
  calicoctl profile remove <PROFILE> [--no-check]
  calicoctl profile <PROFILE> tag show
  calicoctl profile <PROFILE> tag (add|remove) <TAG>
  calicoctl profile <PROFILE> rule add (inbound|outbound) [--at=<POSITION>]
    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
           [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmpv6 [(type <ICMPTYPE> [(code <ICMPCODE>)])]
             [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
             [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
      [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])]
    )]
  calicoctl profile <PROFILE> rule remove (inbound|outbound) (--at=<POSITION>|
    (allow|deny) [(
      (tcp|udp) [(from [(ports <SRCPORTS>)] [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
                [(to   [(ports <DSTPORTS>)] [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmp [(type <ICMPTYPE> [(code <ICMPCODE>)])]
           [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
           [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      icmpv6 [(type <ICMPTYPE> [(code <ICMPCODE>)])]
             [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
             [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])] |
      [(from [(tag <SRCTAG>)] [(cidr <SRCCIDR>)])]
      [(to   [(tag <DSTTAG>)] [(cidr <DSTCIDR>)])]
    )])
  calicoctl profile <PROFILE> rule show
  calicoctl profile <PROFILE> rule json
  calicoctl profile <PROFILE> rule update

Description:
  Modify available profiles and configure rules or tags.

Options:
  --detailed        Show additional information.
  --no-check        Remove a profile without checking if there are endpoints
                    associated with the profile.
  --at=<POSITION>   Specify the position in the chain where the rule should
                    be placed. Default: append at end.

Examples:
  Add and set up a rule to prevent all inbound traffic except pings from the 192.168/16 subnet
  $ calicoctl profile add only-local-pings
  $ calicoctl profile only-local-pings rule add inbound deny icmp
  $ calicoctl profile only-local-pings rule add inbound --at=0 allow from 192.168.0.0/16
"""
import copy
import sys
import re

import docker
import docker.errors
from prettytable import PrettyTable
from pycalico.datastore import Rule
from pycalico.datastore import Rules

from connectors import client, DOCKER_URL
from utils import print_paragraph, DOCKER_LIBNETWORK_VERSION
from pycalico.datastore_datatypes import Profile
from pycalico.util import (validate_characters, validate_ports,
                           validate_icmp_type)
from utils import validate_cidr, validate_cidr_versions


def validate_arguments(arguments):
    """
    Validate argument values:
        <PROFILE>
        <SRCTAG>
        <SRCCIDR>
        <DSTTAG>
        <DSTCIDR>
        <ICMPTYPE>
        <ICMPCODE>
        <SRCPORTS>
        <DSTPORTS>

    Arguments not validated:
        <POSITION>

    :param arguments: Docopt processed arguments
    """
    # Validate Profiles
    profile_ok = True
    if arguments.get("<PROFILE>") is not None:
        profile = arguments.get("<PROFILE>")
        profile_ok = validate_characters(profile)

    # Validate tags
    tag_src_ok = (arguments.get("<SRCTAG>") is None or
                validate_characters(arguments["<SRCTAG>"]))
    tag_dst_ok = (arguments.get("<DSTTAG>") is None or
                validate_characters(arguments["<DSTTAG>"]))

    # Validate IPs
    cidr_ok = True
    cidr_list = []
    for arg in ["<SRCCIDR>", "<DSTCIDR>"]:
        if arguments.get(arg) is not None:
            cidr_list.append(arguments[arg])
            cidr_ok = validate_cidr(arguments[arg])
            if not cidr_ok:
                break

    icmp_ok = True
    for arg in ["<ICMPCODE>", "<ICMPTYPE>"]:
        if arguments.get(arg) is not None:
            icmp_ok = validate_icmp_type(arguments[arg])
            if not icmp_ok:
                break

    ports_ok = True
    for arg in ["<SRCPORTS>", "<DSTPORTS>"]:
        if arguments.get(arg) is not None:
            ports_ok = validate_ports(arguments[arg])
            if not ports_ok:
                break

    cidr_versions_ok = True
    if cidr_list:
        ip_version = None
        if arguments.get("icmp"):
            ip_version = 4
        elif arguments.get("icmpv6"):
            ip_version = 6
        cidr_versions_ok = validate_cidr_versions(cidr_list,
                                                  ip_version=ip_version)

    # Print error message
    if not profile_ok:
        print_paragraph("Profile names must be < 40 character long and can "
                        "only contain numbers, letters, dots, dashes and "
                        "underscores.")
    if not (tag_src_ok and tag_dst_ok):
        print_paragraph("Tags names can only contain numbers, letters, dots, "
                        "dashes and underscores.")
    if not cidr_ok:
        print "Invalid CIDR specified."
    if not icmp_ok:
        print "Invalid ICMP type or ICMP code specified."
    if not ports_ok:
        print "Invalid SRCPORTS or DSTPORTS specified."
    if not cidr_versions_ok:
        print "Invalid or unmatching IP versions for SRCCIDR/DSTCIDR."

    # Exit if not valid
    if not (profile_ok and tag_src_ok and tag_dst_ok
            and cidr_ok and icmp_ok and ports_ok and cidr_versions_ok):
        sys.exit(1)


def profile(arguments):
    """
    Main dispatcher for profile commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
    validate_arguments(arguments)

    if arguments.get("tag") and not arguments.get("rule"):
        if arguments.get("show"):
            profile_tag_show(arguments.get("<PROFILE>"))
        elif arguments.get("add"):
            profile_tag_add(arguments.get("<PROFILE>"),
                            arguments.get("<TAG>"))
        elif arguments.get("remove"):
            profile_tag_remove(arguments.get("<PROFILE>"),
                               arguments.get("<TAG>"))
    elif arguments.get("rule"):
        if arguments.get("show"):
            profile_rule_show(arguments.get("<PROFILE>"),
                              human_readable=True)
        elif arguments.get("json"):
            profile_rule_show(arguments.get("<PROFILE>"),
                              human_readable=False)
        elif arguments.get("update"):
            profile_rule_update(arguments.get("<PROFILE>"))
        elif arguments.get("add") or arguments.get("remove"):
            operation = "add" if arguments.get("add") else "remove"
            action = "allow" if arguments.get("allow") else "deny"
            direction = ("inbound" if arguments.get("inbound")
                         else "outbound")
            if arguments.get("tcp"):
                protocol = "tcp"
            elif arguments.get("udp"):
                protocol = "udp"
            elif arguments.get("icmp"):
                protocol = "icmp"
            elif arguments.get("icmpv6"):
                protocol = "icmpv6"
            else:
                protocol = None
            src_ports = parse_ports(arguments.get("<SRCPORTS>"))
            dst_ports = parse_ports(arguments.get("<DSTPORTS>"))
            position = arguments.get("--at")
            if position is not None:
                try:
                    position = int(position)
                except ValueError:
                    sys.exit(1)
            profile_rule_add_remove(
                operation,
                arguments.get("<PROFILE>"),
                position,
                action,
                direction,
                protocol=protocol,
                icmp_type=arguments.get("<ICMPTYPE>"),
                icmp_code=arguments.get("<ICMPCODE>"),
                src_net=arguments.get("<SRCCIDR>"),
                src_tag=arguments.get("<SRCTAG>"),
                src_ports=src_ports,
                dst_net=arguments.get("<DSTCIDR>"),
                dst_tag=arguments.get("<DSTTAG>"),
                dst_ports=dst_ports,
            )
    elif arguments.get("add"):
        profile_add(arguments.get("<PROFILE>"))
    elif arguments.get("remove"):
        profile_remove(arguments.get("<PROFILE>"), arguments.get("--no-check"))
    elif arguments.get("show"):
        profile_show(arguments.get("--detailed"))


def profile_add(profile_name):
    """
    Create a policy profile with the given name.
    :param profile_name: The name for the profile.
    :return: None.
    """
    # Check if the profile exists.
    if client.profile_exists(profile_name):
        print "Profile %s already exists." % profile_name
    else:
        # Create the profile.
        client.create_profile(profile_name)
        print "Created profile %s" % profile_name


def profile_remove(profile_name, nocheck):
    """
    Remove a profile as long as it does not contain any endpoints.
    Allow user to explicitly remove the profile if desired.
    :param profile_name: The name of the profile to remove.
    :param nocheck: Flag saying to remove profile regardless of endpoints.
    :return: None.
    """
    # Check if the profile exists.
    if client.profile_exists(profile_name):
        rm_profile = False
        # Check that the nocheck flag was used
        if nocheck:
            rm_profile = True
        else:
            # Check if the the profile has endpoints associated with it
            members = client.get_profile_members(profile_name)
            if not members:
                rm_profile = True
        # Remove the profile if criteria was met
        if rm_profile:
            client.remove_profile(profile_name)
            print "Deleted profile %s" % profile_name
        else:
            # Members must exist if this branch is reached
            print "Cannot remove profile - profile in use by endpoint(s).\n" + \
                  "Use the '--no-check' flag to remove the profile anyway."
    else:
        print "Profile %s not found." % profile_name


def profile_show(detailed):
    profiles = client.get_profile_names()

    if detailed:
        x = PrettyTable(["Name", "Host", "Orchestrator ID", "Workload ID",
                         "Endpoint ID", "State"])
        for name in profiles:
            members = client.get_profile_members(name)
            if not members:
                x.add_row([name, "None", "None", "None", "None", "None"])
                continue

            for endpoint in members:
                x.add_row([name,
                           endpoint.hostname,
                           endpoint.orchestrator_id,
                           endpoint.workload_id,
                           endpoint.endpoint_id,
                           endpoint.state])
    else:
        x = PrettyTable(["Name"])
        for name in profiles:
            x.add_row([name])

    print x.get_string(sortby="Name")


def profile_tag_show(name):
    """Show the tags on the profile."""
    try:
        nmp = NetworkMappedProfile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    for tag in nmp.profile.tags:
        print tag


def profile_tag_add(name, tag):
    """
    Add a tag to the profile.
    :param name: Profile name
    :param tag: Tag name
    :return: None
    """
    try:
        nmp = NetworkMappedProfile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    nmp.profile.tags.add(tag)
    nmp.update_tags()
    print "Tag %s added to profile %s" % (tag, name)


def profile_tag_remove(name, tag):
    """
    Remove a tag from the profile.
    :param name: Profile name
    :param tag: Tag name
    :return: None
    """
    try:
        nmp = NetworkMappedProfile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    try:
        nmp.profile.tags.remove(tag)
    except KeyError:
        print "Tag %s is not on profile %s" % (tag, name)
        sys.exit(1)
    nmp.update_tags()
    print "Tag %s removed from profile %s" % (tag, name)


def profile_rule_show(name, human_readable=False):
    """Show the rules on the profile."""
    try:
        nmp = NetworkMappedProfile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if human_readable:
        print "Inbound rules:"
        for i, rule in enumerate(nmp.profile.rules.inbound_rules, start=1):
            print " %3d %s" % (i, rule.pprint())
        print "Outbound rules:"
        for i, rule in enumerate(nmp.profile.rules.outbound_rules, start=1):
            print " %3d %s" % (i, rule.pprint())
    else:
        print nmp.profile.rules.to_json(indent=2)
        print ""


def profile_rule_update(name):
    """Update the rules on the profile"""
    try:
        nmp = NetworkMappedProfile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    # Read in the JSON from standard in.
    rules_str = sys.stdin.read()
    rules = Rules.from_json(rules_str)
    if rules.id != name:
        print 'Rules JSON "id"=%s doesn\'t match profile name %s.' % \
              (rules.id, name)
        sys.exit(1)

    nmp.profile.rules = rules
    nmp.update_rules()
    print "Successfully updated rules on profile %s" % name


def profile_rule_add_remove(
        operation,
        name, position, action, direction,
        protocol=None,
        icmp_type=None, icmp_code=None,
        src_net=None, src_tag=None, src_ports=None,
        dst_net=None, dst_tag=None, dst_ports=None):
    """
    Add or remove a rule from a profile.

    Arguments not documented below are passed through to the rule.

    :param operation: "add" or "remove".
    :param name: Name of the profile.
    :param position: Position to insert/remove rule or None for the default.
    :param action: Rule action: "allow" or "deny".
    :param direction: "inbound" or "outbound".

    :return:
    """
    if icmp_type is not None:
        icmp_type = int(icmp_type)
    if icmp_code is not None:
        icmp_code = int(icmp_code)

    # Convert the input into a Rule.
    rule_dict = {k: v for (k, v) in locals().iteritems()
                 if k in Rule.ALLOWED_KEYS and v is not None}
    rule_dict["action"] = action
    if (protocol not in ("tcp", "udp")) and (src_ports is not None or
                                             dst_ports is not None):
        print "Ports are not valid with protocol %r" % protocol
        sys.exit(1)
    rule = Rule(**rule_dict)

    # Get the profile.
    try:
        nmp = NetworkMappedProfile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if direction == "inbound":
        rules = nmp.profile.rules.inbound_rules
    else:
        rules = nmp.profile.rules.outbound_rules

    if operation == "add":
        if position is None:
            # Default to append.
            position = len(rules) + 1
        if not 0 < position <= len(rules) + 1:
            print "Position %s is out-of-range." % position
        if rule in rules:
            print "Rule already present, skipping."
            return
        rules.insert(position - 1, rule)  # Accepts 0 and len(rules).
    else:
        # Remove.
        if position is not None:
            # Position can only be used on its own so no need to examine the
            # rule.
            if 0 < position <= len(rules):  # 1-indexed
                rules.pop(position - 1)
            else:
                print "Rule position out-of-range."
        else:
            # Attempt to match the rule.
            try:
                rules.remove(rule)
            except ValueError:
                print "Rule not found."
                sys.exit(1)
    nmp.update_rules()


def parse_ports(ports_str):
    """
    Parse a string representing a port list into a list of ports and
    port ranges.

    Returns None if the input is None.

    :param StringTypes|NoneType ports_str: string representing a port list.
        Examples: "1" "1,2,3" "1:3" "1,2,3:4"
    :return list[StringTypes|int]|NoneType: list of ports or None.
    """
    if ports_str is None:
        return None
    # We allow ranges with : or - but convert to :, which is what the data
    # model uses.
    if not re.match(r'^(\d+([:-]\d+)?)(,\d+([:-]\d+)?)*$',
                    ports_str):
        print_paragraph("Ports: %r are invalid; expecting a comma-separated "
                        "list of ports and port ranges." % ports_str)
        sys.exit(1)
    splits = ports_str.split(",")
    parsed_ports = []
    for split in splits:
        m = re.match(r'^(\d+)[:-](\d+)$', split)
        if m:
            # Got a range, canonicalise it.
            min = int(m.group(1))
            max = int(m.group(2))
            if min > max:
                print "Port range minimum (%s) > maximum (%s)." % (min, max)
                sys.exit(1)
            if not (0 <= min <= 65535):
                print "Port minimum (%s) out-of-range." % min
                sys.exit(1)
            if not (0 <= max <= 65535):
                print "Port maximum (%s) out-of-range." % max
                sys.exit(1)
            parsed_ports.append("%s:%s" % (min, max))
        else:
            # Should be a lone port, convert to int.
            port = int(split)
            if not (0 <= port <= 65535):
                print "Port (%s) out-of-range." % min
                sys.exit(1)
            parsed_ports.append(port)
    return parsed_ports


class NoDockerNetwork(BaseException):
    """
    Exception indicating that a docker network does not exist.
    """
    def __init__(self, name):
        self.name = name


class NetworkMappedProfile(object):
    """
    Class encapsulating a profile and the mappings between the Docker
    libnetwork naming and the profile naming.  Use this class for loading and
    updating all existing profiles - it detects whether the profile is a
    Docker network based profile and performs all necessary mappings.

    For new profiles created using calicoctl it is not necessary to perform
    any mappings since these profiles are not related to Docker networks.
    """

    def __init__(self, name):
        self._id_by_name = {}
        """
        Docker network IDs keyed off the Docker network names.
        """

        self._name_by_id = {}
        """
        Docker network names keyed off the Docker network IDs.
        """

        self.docker_client = None
        """
        Docker client of version 1.21 to allow us inspect networks.  We
        initialise this only if we are attempting to do a Docker network
        inspection to convert between network names and IDs (i.e. between the
        "nice" Docker network name and the ID that is used to name the profile.
        """

        self.profile = self._load_profile(name)
        """
        The mapped profile. The caller should make modifications to this
        profile, and update the datastore by calling either the update_tags()
        or update_rules() methods on this class.
        """

    def _load_profile(self, name):
        """
        Load the profile from the datastore.

        If the profile exists under the supplied name, return the profile as
        is.

        If the profile does not exist under the supplied name, perform a docker
        network inspect to determine if this is a network name and to look up
        the network ID.  Look up the profile based on the network ID, and map
        the profile name and the tags to the appropriate network name.  This
        assumes the tags and profiles names are the same (which by default they
        are).

        :param name:  The profile or network name.
        :return: The loaded and (if required) translated profile.
        """
        try:
            # Load and store the profile.
            profile = client.get_profile(name)
        except KeyError as e:
            # Profile is not found, check to see if it configured as a Docker
            # network, and if so use the network ID to locate the profile.  The
            # The profile will need converting to use network names rather than
            # profile names and tags.
            try:
                network_id = self._get_id_from_name(name)
            except NoDockerNetwork:
                raise e
            else:
                # Found the network, get the profile and translate from IDs
                # to names.
                profile = client.get_profile(network_id)
                profile = self._translate_profile(profile, self._get_name_from_id)

        return profile

    def update_tags(self):
        """
        Update the tags in the profile.
        :return: None.
        """
        client.profile_update_tags(self._translate_profile_for_datastore())

    def update_rules(self):
        """
        Update the tags in the profile.
        :return:
        """
        client.profile_update_rules(self._translate_profile_for_datastore())

    def is_docker_network_profile(self):
        """
        Whether the profile stored in this class represents a Docker network
        profile or not.
        :return:  True if this is a Docker network profile.  False otherwise.
        """
        # If we have a name to ID mapping then this is a Docker network
        # profile.
        return bool(self._id_by_name)

    def _translate_profile_for_datastore(self):
        """
        Translate the profile for updating in the datastore.  This also checks
        the updated tags reference real Docker networks when the profile is
        for a Docker network.

        :return: The translated profile.
        """
        # If this is not a Docker network profile then just return the profile
        # unchanged.
        if not self.is_docker_network_profile():
            return self.profile

        # This is a Docker network profile, so translate from names to IDs.
        try:
            profile = self._translate_profile(self.profile,
                                              self._get_id_from_name)
        except NoDockerNetwork as e:
            # A tag in the profile does not reference a valid Docker network.
            print_paragraph("You are referencing a Docker network (%s) that "
                            "does not exist.  Create the network first and "
                            "then update this profile rule to reference "
                            "it." % e.name)
            sys.exit(1)
        else:
            return profile

    def _translate_profile(self, profile, mapping_fn):
        """
        Translate the profile by converting between Docker network names and
        IDs in the profile name and tags.  The direction of transalation
        depends on the mapping function provided.

        This should only be called for Docker network profiles.
        :return: The translated profile.
        """
        # Create a new profile mapping the name of the one supplied.
        translated_profile = Profile(mapping_fn(profile.name))

        # Add the translated tags.
        for tag in profile.tags:
            translated_profile.tags.add(mapping_fn(tag))

        # Add the updated rules.
        for rule in profile.rules.inbound_rules:
            rule = copy.copy(rule)
            if "src_tag" in rule:
                rule["src_tag"] = mapping_fn(rule["src_tag"])
            if "dst_tag" in rule:
                rule["dst_tag"] = mapping_fn(rule["dst_tag"])
            translated_profile.rules.inbound_rules.append(rule)
        for rule in profile.rules.outbound_rules:
            rule = copy.copy(rule)
            if "src_tag" in rule:
                rule["src_tag"] = mapping_fn(rule["src_tag"])
            if "dst_tag" in rule:
                rule["dst_tag"] = mapping_fn(rule["dst_tag"])
            translated_profile.rules.outbound_rules.append(rule)

        return translated_profile

    def _get_name_from_id(self, network_id):
        """
        Get the Docker network name from the network ID.  If the network does
        not exist we just use the network ID - this allows broken profiles to
        be viewed and modified.

        :param network_id: The network ID.
        :return: The Docker network name if it exists, otherwise return the
                 network ID.
        """
        # Police against empty ids.
        if not network_id:
            return network_id

        # Check if we have already looked up the network based on the tag.
        name = self._name_by_id.get(network_id)
        if name:
            return name

        # The tag to network mapping is not found.  use the tag to perform a
        # Docker network inspect, and check again.
        self._network_inspect(network_id)
        name = self._name_by_id.get(network_id)
        if name:
            return name

        # The mapping is still not found, so we can't map the ID (used as a
        # profile tag) to a Docker network name.  In that case just return the
        # ID unchanged.  We also store the mapping so that when pushing changes
        # back down again we can ignore rules with these invalid tags - this is
        # necessary when there are multiple broken rules and you can only
        # delete one at a time.
        self._name_by_id[network_id] = network_id
        self._id_by_name[network_id] = network_id
        return network_id

    def _get_id_from_name(self, name):
        """
        Get the profile tag name from the Docker network name.  If the name
        cannot be mapped to a Docker Network then raise a NoDockerNetwork
        exception.

        :param name: The Docker network name.
        :return: The profile tag name.  If the Docker network name is not
          recognised then raise a NoDockerNetwork exception.
        """
        # Police against empty network names
        if not name:
            return name

        # Check if we have already looked up the tag based on the network.
        network_id = self._id_by_name.get(name)
        if network_id:
            return network_id

        # The network to tag mapping is not found.  use the net to perform a
        # Docker network inspect, and check again.
        self._network_inspect(name)
        network_id = self._id_by_name.get(name)
        if network_id:
            return network_id

        # The network is not found so raise an Exception.
        raise NoDockerNetwork(name)

    def _network_inspect(self, name):
        """
        Perform a Docker network inspect and store the mapping.
        :param name: The network ID or name.
        :return: None.
        """
        # We need to be using a minimum version of Docker for handling
        # libnetwork.  Create an appropriate Docker client - if Docker is not
        # running at an appropriate version then there is nothing more to do
        # since we can't be running with Calico as a Docker network.
        #
        # We only create this client when we need to perform a network
        # inspection.  It is not possible to update the version of the client
        # used by other calicoctl commands because we need to support older
        # versions of Docker.
        if not self.docker_client:
            try:
                self.docker_client = docker.Client(version=DOCKER_LIBNETWORK_VERSION,
                                                   base_url=DOCKER_URL)
            except docker.errors.APIError:
                return

        try:
            network = self.docker_client.inspect_network(name)
        except docker.errors.APIError:
            pass
        else:
            network_id = network['Id']
            name = network['Name']
            self._id_by_name[name] = network_id
            self._name_by_id[network_id] = name
