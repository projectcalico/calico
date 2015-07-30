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
  calicoctl endpoint show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>] [--endpoint=<ENDPOINT_ID>] [--detailed]
  calicoctl endpoint <ENDPOINT_ID> profile (append|remove|set) [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]  [<PROFILES>...]
  calicoctl endpoint <ENDPOINT_ID> profile show [--host=<HOSTNAME>] [--orchestrator=<ORCHESTRATOR_ID>] [--workload=<WORKLOAD_ID>]

Description:
  Configure or show endpoints assigned to existing containers

Options:
 --detailed                         Show additional information
 --host=<HOSTNAME>                  Filters endpoints on a specific host
 --orchestrator=<ORCHESTRATOR_ID>   Filters endpoints created on a specific orchestrator
 --workload=<WORKLOAD_ID>           Filters endpoints on a specific workload
 --endpoint=<ENDPOINT_ID>           Filters endpoints with a specific endpoint ID

Examples:
    Show all endpoints belonging to 'host1':
        $ calicoctl endpoint show --host=host1

    Add a profile called 'profile-A' to the endpoint a1b2c3d4:
        $ calicoctl endpoint a1b2c3d4 profile append profile-A

    Add a profile called 'profile-A' to the endpoint a1b2c3d4, but faster,
    by providing more specific filters:
        $ calicoctl endpoint a1b2c3d4 profile append profile-A --host=host1 --orchestrator=docker --workload=f9e8d7e6
"""
import sys
from collections import defaultdict

from prettytable import PrettyTable
from pycalico.datastore_errors import ProfileAlreadyInEndpoint
from pycalico.datastore_errors import MultipleEndpointsMatch
from pycalico.datastore_errors import ProfileNotInEndpoint

from connectors import client
from utils import print_paragraph
from utils import validate_characters


def validate_arguments(arguments):
    """
    Validate argument values:
        <PROFILES>

    Arguments not validated:
        <HOSTNAME>
        <ORCHESTRATOR_ID>
        <WORKLOAD_ID>
        <ENDPOINT_ID>

    :param arguments: Docopt processed arguments
    """
    # List of valid characters that Felix permits
    valid_chars = '[a-zA-Z0-9_\.\-]'

    # Validate Profiles
    profile_ok = True
    profiles = arguments.get("<PROFILES>")
    if profiles is not None:
        for profile in profiles:
            profile_ok = validate_characters(profile)

    if not profile_ok:
        print_paragraph("Profile names must be < 40 character long and can "
                        "only contain numbers, letters, dots, dashes and "
                        "underscores.")
        sys.exit(1)


class EndpointSummary(object):
    """
    Simply holder class used to compile workload and endpoint summaries
    (see endpoint_show() command).
    """
    def __init__(self):
        self.workload_ids = set()
        self.num_endpoints = 0

    def add_endpoint(self, endpoint):
        """
        Add an endpoint.  We track unique workload IDs and maintain a count
        of endpoints.

        :param endpoint:  An Endpoint object.
        """
        self.num_endpoints += 1
        self.workload_ids.add(endpoint.workload_id)


def endpoint(arguments):
    """
    Main dispatcher for endpoint commands. Calls the corresponding helper
    function.

    :param arguments: A dictionary of arguments already processed through
    this file's docstring with docopt.
    :return: None
    """
    validate_arguments(arguments)

    if arguments.get("profile"):
        if arguments.get("append"):
            endpoint_profile_append(arguments.get("--host"),
                                    arguments.get("--orchestrator"),
                                    arguments.get("--workload"),
                                    arguments.get("<ENDPOINT_ID>"),
                                    arguments['<PROFILES>'])
        elif arguments.get("remove"):
            endpoint_profile_remove(arguments.get("--host"),
                                    arguments.get("--orchestrator"),
                                    arguments.get("--workload"),
                                    arguments.get("<ENDPOINT_ID>"),
                                    arguments['<PROFILES>'])
        elif arguments.get("set"):
            endpoint_profile_set(arguments.get("--host"),
                                 arguments.get("--orchestrator"),
                                 arguments.get("--workload"),
                                 arguments.get("<ENDPOINT_ID>"),
                                 arguments['<PROFILES>'])
        elif arguments.get("show"):
            endpoint_profile_show(arguments.get("--host"),
                                  arguments.get("--orchestrator"),
                                  arguments.get("--workload"),
                                  arguments.get("<ENDPOINT_ID>"))
    else:
        # calicoctl endpoint show
        endpoint_show(arguments.get("--host"),
                      arguments.get("--orchestrator"),
                      arguments.get("--workload"),
                      arguments.get("--endpoint"),
                      arguments.get("--detailed"))


def endpoint_show(hostname, orchestrator_id, workload_id, endpoint_id,
                  detailed):
    """
    List the profiles for a given endpoint. All parameters will be used to
    filter down which endpoints should be shown.

    :param endpoint_id: The endpoint ID.
    :param workload_id: The workload ID.
    :param orchestrator_id: The orchestrator ID.
    :param hostname: The hostname.
    :param detailed: Optional flag, when set to True, will provide more
    information in the shown table
    :return: Nothing
    """
    endpoints = client.get_endpoints(hostname=hostname,
                                     orchestrator_id=orchestrator_id,
                                     workload_id=workload_id,
                                     endpoint_id=endpoint_id)

    if detailed:
        headings = ["Hostname",
                    "Orchestrator ID",
                    "Workload ID",
                    "Endpoint ID",
                    "Addresses",
                    "MAC",
                    "Profiles",
                    "State"]
        x = PrettyTable(headings, sortby="Hostname")

        for endpoint in endpoints:
            addresses = "\n".join([str(net) for net in
                                   endpoint.ipv4_nets | endpoint.ipv6_nets])
            x.add_row([endpoint.hostname,
                       endpoint.orchestrator_id,
                       endpoint.workload_id,
                       endpoint.endpoint_id,
                       addresses,
                       endpoint.mac,
                       ','.join(endpoint.profile_ids),
                       endpoint.state])
    else:
        headings = ["Hostname",
                    "Orchestrator ID",
                    "Number of Workloads",
                    "Number of Endpoints"]
        x = PrettyTable(headings, sortby="Hostname")

        # The summary table has one entry for each host/orchestrator
        # combination.  We create a dictionary to maintain the summary
        # information, using the (hostname, orchestrator_id) as the unique
        # key, with a value of an EndpointSummary object to store unique
        # workload IDs and a count of endpoint IDs.
        #
        # We use a default dict to automatically create an "empty" (zero count)
        # EndpointSummary for each new table entry.
        host_orch_summary = defaultdict(EndpointSummary)
        for endpoint in endpoints:
            key = (endpoint.hostname, endpoint.orchestrator_id)
            summary = host_orch_summary[key]
            summary.add_endpoint(endpoint)

        # This table has one entry for each host/orchestrator combination.
        for key, summary in host_orch_summary.iteritems():
            hostname, orchestrator_id = key
            x.add_row([hostname,
                       orchestrator_id,
                       len(summary.workload_ids),
                       summary.num_endpoints])
                
    print str(x) + "\n"


def endpoint_profile_append(hostname, orchestrator_id, workload_id,
                            endpoint_id, profile_names):
    """
    Append a list of profiles to the container endpoint profile list.

    The hostname, orchestrator_id, workload_id, and endpoint_id are all
    optional parameters used to determine which endpoint is being targeted.
    The more parameters used, the faster the endpoint query will be. The
    query must be specific enough to match a single endpoint or it will fail.

    The profile list may not contain duplicate entries, invalid profile names,
    or profiles that are already in the containers list.

    :param hostname: The host that the targeted endpoint resides on.
    :param orchestrator_id: The orchestrator that created the targeted endpoint.
    :param workload_id: The ID of workload which created the targeted endpoint.
    :param endpoint_id: The endpoint ID of the targeted endpoint.
    :param profile_names: The list of profile names to add to the targeted
                        endpoint.
    :return: None
    """
    # Validate the profile list.
    validate_profile_list(profile_names)
    try:
        client.append_profiles_to_endpoint(profile_names,
                                           hostname=hostname,
                                           orchestrator_id=orchestrator_id,
                                           workload_id=workload_id,
                                           endpoint_id=endpoint_id)
        print_paragraph("Profiles %s appended to %s." %
                        (", ".join(profile_names), endpoint_id))
    except KeyError:
        print "Failed to append profiles to endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)
    except ProfileAlreadyInEndpoint, e:
        print_paragraph("Profile %s is already in endpoint "
                        "profile list" % e.profile_name)
    except MultipleEndpointsMatch:
        print_paragraph("More than 1 endpoint matches the provided criteria.  "
                        "Please provide additional parameters to refine the "
                        "search.")
        sys.exit(1)


def endpoint_profile_set(hostname, orchestrator_id, workload_id,
                         endpoint_id, profile_names):
    """
    Set the complete list of profiles for the container endpoint profile list.

    The hostname, orchestrator_id, workload_id, and endpoint_id are all optional
    parameters used to determine which endpoint is being targeted.
    The more parameters used, the faster the endpoint query will be. The
    query must be specific enough to match a single endpoint or it will fail.

    The profile list may not contain duplicate entries or invalid profile names.

    :param hostname: The host that the targeted endpoint resides on.
    :param orchestrator_id: The orchestrator that created the targeted endpoint.
    :param workload_id: The ID of workload which created the targeted endpoint.
    :param endpoint_id: The endpoint ID of the targeted endpoint.
    :param profile_names: The list of profile names to set on the targeted
    endpoint.

    :return: None
    """
    # Validate the profile list.
    validate_profile_list(profile_names)

    try:
        client.set_profiles_on_endpoint(profile_names,
                                        hostname=hostname,
                                        orchestrator_id=orchestrator_id,
                                        workload_id=workload_id,
                                        endpoint_id=endpoint_id)
        print_paragraph("Profiles %s set for %s." %
                        (", ".join(profile_names), endpoint_id))
    except KeyError:
        print "Failed to set profiles for endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)


def endpoint_profile_remove(hostname, orchestrator_id, workload_id,
                            endpoint_id, profile_names):
    """
    Remove a list of profiles from the endpoint profile list.

    The hostname, orchestrator_id, workload_id, and endpoint_id are all optional
    parameters used to determine which endpoint is being targeted.
    The more parameters used, the faster the endpoint query will be. The
    query must be specific enough to match a single endpoint or it will fail.

    The profile list may not contain duplicate entries, invalid profile names,
    or profiles that are not already in the containers list.

    :param hostname: The host that the targeted endpoint resides on.
    :param orchestrator_id: The orchestrator that created the targeted endpoint.
    :param workload_id: The ID of workload which created the targeted endpoint.
    :param endpoint_id: The endpoint ID of the targeted endpoint.
    :param profile_names: The list of profile names to remove from the targeted
                          endpoint.
    :return: None
    """
    # Validate the profile list.
    validate_profile_list(profile_names)

    try:
        client.remove_profiles_from_endpoint(profile_names,
                                             hostname=hostname,
                                             orchestrator_id=orchestrator_id,
                                             workload_id=workload_id,
                                             endpoint_id=endpoint_id)
        print_paragraph("Profiles %s removed from %s." %
                        (",".join(profile_names), endpoint_id))
    except KeyError:
        print "Failed to remove profiles from endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)
    except ProfileNotInEndpoint, e:
        print_paragraph("Profile %s is not in endpoint profile "
                        "list." % e.profile_name)
    except MultipleEndpointsMatch:
        print "More than 1 endpoint matches the provided criteria. " \
              "Please provide additional parameters to refine the search."
        sys.exit(1)


def endpoint_profile_show(hostname, orchestrator_id, workload_id, endpoint_id):
    """
    List the profiles assigned to a particular endpoint.

    :param hostname: The hostname.
    :param orchestrator_id: The orchestrator ID.
    :param workload_id: The workload ID.
    :param endpoint_id: The endpoint ID.

    :return: None
    """
    try:
        endpoint = client.get_endpoint(hostname=hostname,
                                       orchestrator_id=orchestrator_id,
                                       workload_id=workload_id,
                                       endpoint_id=endpoint_id)
    except MultipleEndpointsMatch:
        print "Failed to list profiles in endpoint.\n"
        print_paragraph("More than 1 endpoint matches the provided "
                        "criteria.  Please provide additional parameters to "
                        "refine the search.")
        sys.exit(1)
    except KeyError:
        print "Failed to list profiles in endpoint.\n"
        print_paragraph("Endpoint %s is unknown to Calico.\n" % endpoint_id)
        sys.exit(1)

    if endpoint.profile_ids:
        x = PrettyTable(["Name"], sortby="Name")
        for name in endpoint.profile_ids:
            x.add_row([name])
        print str(x) + "\n"
    else:
        print "Endpoint has no profiles associated with it."


def validate_profile_list(profile_names):
    """
    Validate a list of profiles.  This checks that each profile name is
    valid and specified only once in the list.

    This method traces and exits upon failure.

    :param profile_names: The list of profiles to check.
    :return: None
    """
    compiled = set()
    for profile_name in profile_names:
        if not client.profile_exists(profile_name):
            print "Profile with name %s was not found." % profile_name
            sys.exit(1)
        if profile_name in compiled:
            print "Profile with name %s was specified more than " \
                  "once." % profile_name
            sys.exit(1)
        compiled.add(profile_name)
