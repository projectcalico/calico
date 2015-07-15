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
import sys
import re
from prettytable import PrettyTable
from pycalico.datastore import Rule
from pycalico.datastore import Rules
from utils import client
from utils import print_paragraph

def profile(arguments):
    """
    Main dispatcher for profile commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt
    :return: None
    """
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
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    for tag in profile.tags:
        print tag


def profile_tag_add(name, tag):
    """
    Add a tag to the profile.
    :param name: Profile name
    :param tag: Tag name
    :return: None
    """
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    profile.tags.add(tag)
    client.profile_update_tags(profile)
    print "Tag %s added to profile %s" % (tag, name)


def profile_tag_remove(name, tag):
    """
    Remove a tag from the profile.
    :param name: Profile name
    :param tag: Tag name
    :return: None
    """
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    try:
        profile.tags.remove(tag)
    except KeyError:
        print "Tag %s is not on profile %s" % (tag, name)
        sys.exit(1)
    client.profile_update_tags(profile)
    print "Tag %s removed from profile %s" % (tag, name)


def profile_rule_show(name, human_readable=False):
    """Show the rules on the profile."""
    try:
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if human_readable:
        print "Inbound rules:"
        for i, rule in enumerate(profile.rules.inbound_rules, start=1):
            print " %3d %s" % (i, rule.pprint())
        print "Outbound rules:"
        for i, rule in enumerate(profile.rules.outbound_rules, start=1):
            print " %3d %s" % (i, rule.pprint())
    else:
        print profile.rules.to_json(indent=2)
        print ""


def profile_rule_update(name):
    """Update the rules on the profile"""
    try:
        profile = client.get_profile(name)
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

    profile.rules = rules
    client.profile_update_rules(profile)
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
        profile = client.get_profile(name)
    except KeyError:
        print "Profile %s not found." % name
        sys.exit(1)

    if direction == "inbound":
        rules = profile.rules.inbound_rules
    else:
        rules = profile.rules.outbound_rules

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
    client.profile_update_rules(profile)


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
