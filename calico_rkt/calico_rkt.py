#!/usr/bin/env python
from __future__ import print_function
import socket
import functools
import json
import os
import sys
from subprocess import check_output, CalledProcessError, check_call

from netaddr import IPAddress, IPNetwork, AddrFormatError
from pycalico import netns
from pycalico.ipam import IPAMClient, SequentialAssignment
from pycalico.netns import Namespace
from pycalico.datastore_datatypes import Rules
from pycalico.datastore import IF_PREFIX, DatastoreClient
from pycalico.datastore_errors import PoolNotFound

print_stderr = functools.partial(print, file=sys.stderr)


input_ = ''.join(sys.stdin.readlines()).replace('\n', '')
input_json = json.loads(input_)

# Append to existing env, to avoid losing PATH etc.
# TODO-PAT: This shouldn't be hardcoded
env = os.environ.copy()
ETCD_AUTHORITY_ENV = 'ETCD_AUTHORITY'
env[ETCD_AUTHORITY_ENV] = 'localhost:2379'

# PROFILE_LABEL = 'CALICO_PROFILE'
# ETCD_PROFILE_PATH = '/calico/'

ORCHESTRATOR_ID = "rkt"
HOSTNAME = socket.gethostname()
NETNS_ROOT= '/var/lib/rkt/pods/run'

def main():
    mode = env['CNI_COMMAND']

    if mode == 'init':
        print_stderr('No initialization work to perform')
    elif mode == 'ADD':
        print_stderr('Executing Calico pod-creation plugin')
        create(
            container_id=env['CNI_CONTAINERID']
            )
    elif mode == 'DEL':
        print_stderr('Executing Calico pod-deletion plugin')
        delete(
            container_id=env['CNI_CONTAINERID']
            )

def create(container_id):
    """"Handle rkt pod-create event."""
    print_stderr('Configuring pod %s' % container_id, file=sys.stderr)
    netns_path='%s/%s/%s' % (NETNS_ROOT, container_id, env['CNI_NETNS'])
    _datastore_client = IPAMClient()

    try:
        endpoint, ip = _create_calico_endpoint(container_id=container_id,
                                            netns_path=netns_path,
                                            client=_datastore_client)

        _create_profile(endpoint=endpoint, 
                        profile_name=input_json['name'], 
                        ip=ip,
                        client=_datastore_client)
    except CalledProcessError as e:
        print_stderr('Error code %d creating pod networking: %s\n%s' % (
            e.returncode, e.output, e))
        sys.exit(1)
    print_stderr('Finished Creating pod %s' % container_id)    

def delete(container_id):
    """Cleanup after a pod."""
    print_stderr('Deleting pod %s' % container_id, file=sys.stderr)

    _datastore_client = IPAMClient()

    # Remove the profile for the workload.
    _container_remove(hostname=HOSTNAME,
                        orchestrator_id=ORCHESTRATOR_ID,
                        container_id=container_id,
                        client=_datastore_client)

    # Delete profile
    try:
        _datastore_client.remove_profile(input_json['name'])
    except:
        print_stderr("Cannot remove profile %s; Profile cannot be found." % container_id)

def _create_calico_endpoint(container_id, netns_path, client):
    """Configure the Calico interface for a pod."""
    print_stderr('Configuring Calico networking.', file=sys.stderr)

    interface = env['CNI_IFNAME']

    endpoint, ip = _container_add(hostname=HOSTNAME,
                                orchestrator_id=ORCHESTRATOR_ID,
                                container_id=container_id,
                                netns_path=netns_path,
                                interface=interface,
                                client=client)
    print_stderr('Finished configuring network interface', file=sys.stderr)
    return endpoint, ip

def _container_add(hostname, orchestrator_id, container_id, netns_path, interface, client):
    """
    Add a container to Calico networking with the given IP
    Return Endpoint object
    """
    try:
        _ = client.get_endpoint(
            hostname=hostname,
            orchestrator_id=orchestrator_id,
            workload_id=container_id
        )
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        print_stderr("This container has already been configured with Calico Networking.")
        sys.exit(1)

    # Allocate and Assign ip address through IPAM Client
    ip = _allocate_IP()

    # Create Endpoint object
    try:
        ep = client.create_endpoint(HOSTNAME, ORCHESTRATOR_ID,
                                      container_id, [IPAddress(ip)])
    except AddrFormatError:
        print_stderr("This node is not configured for IPv%d. Unassigning IP "\
                      "address %s then exiting."  % ip.version, ip)
        client.unassign_address(IPNetwork(input_json['ipam']['subnet']), ip)
        sys.exit(1)

    # Create the veth, move into the container namespace, add the IP and
    # set up the default routes.
    ep.mac = ep.provision_veth(Namespace(netns_path), interface)
    client.set_endpoint(ep)

    # Let the caller know what endpoint was created.
    return ep, ip

def _container_remove(hostname, orchestrator_id, container_id, client):
    """
    Remove the indicated container on this host from Calico networking
    """
    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint = client.get_endpoint(
            hostname=hostname,
            orchestrator_id=orchestrator_id,
            workload_id=container_id
        )
    except KeyError:
        print_stderr("Container %s doesn't contain any endpoints" % container_id)
        sys.exit(1)

    # Remove any IP address assignments that this endpoint has
    for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
        assert(net.size == 1)
        client.unassign_address(None, net.ip)

    # Remove the endpoint
    netns.remove_veth(endpoint.name)

    # Remove the container from the datastore.
    client.remove_workload(hostname, orchestrator_id, container_id)

    print_stderr("Removed Calico interface from %s" % container_id)

def _create_profile(endpoint, profile_name, ip, client):
    """
    Configure the calico profile for a pod.

    Currently assumes one pod with each name.
    """
    print_stderr('Configuring Pod Profile: %s' % profile_name)

    if client.profile_exists(profile_name):
        print_stderr("Profile with name %s already exists, applying to endpoint." % (profile_name))

    else:
        client.create_profile(profile_name)
        # _apply_rules(profile_name, client)

    # Also set the profile for the workload.
    print_stderr('Setting profile %s on endpoint %s' %
                 (profile_name, endpoint.endpoint_id))
    client.set_profiles_on_endpoint(
        [profile_name], endpoint_id=endpoint.endpoint_id
    )
    print_stderr("Finished configuring profile.")
    dump = json.dumps(
        {
            "ip4": {
                "ip": "%s/24" % ip
            }
        })
    print(dump)

def _create_rules(id_):
    rules_dict = {
        "id": id_,
        "inbound_rules": [
            {
                "action": "allow",
            },
        ],
        "outbound_rules": [
            {
                "action": "allow",
            },
        ],
    }
    rules_json = json.dumps(rules_dict, indent=2)
    rules = Rules.from_json(rules_json)
    return rules

def _apply_rules(profile_name, client):
    """
    Generate a new profile with the default "allow all" rules.
    :param profile_name: The profile to update
    :type profile_name: string
    :return:
    """
    try:
        profile = client.get_profile(profile_name)
    except:
        print_stderr("Error: Could not apply rules. Profile not found: %s, exiting" % profile_name)
        sys.exit(1)

    profile.rules = _create_rules(profile_name)
    client.profile_update_rules(profile)
    print_stderr("Finished applying rules.")

def _allocate_IP():
    """
    Determine next available IP for pool in input_ and assign it
    """
    pool = input_json['ipam']['subnet']
    candidate = SequentialAssignment().allocate(IPNetwork(pool))
    print_stderr("Using IP %s" % candidate)
    return candidate

if __name__ == '__main__':
    main()
