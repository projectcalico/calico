# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import print_function
import socket
import functools
import logging
import json
import os
import sys

from subprocess import check_output, CalledProcessError, check_call
from netaddr import IPAddress, IPNetwork, AddrFormatError

from pycalico import netns
from pycalico.ipam import IPAMClient, SequentialAssignment
from pycalico.netns import Namespace
from pycalico.datastore_datatypes import Rules, IPPool
from pycalico.datastore import IF_PREFIX
from pycalico.datastore_errors import PoolNotFound

ETCD_AUTHORITY_ENV = 'ETCD_AUTHORITY'
LOG_DIR = '/var/log/calico/calico-rkt'

ORCHESTRATOR_ID = "rkt"
HOSTNAME = socket.gethostname()
NETNS_ROOT = '/var/lib/rkt/pods/run'

_log = logging.getLogger(__name__)
datastore_client = IPAMClient()


def calico_rkt(args):
    """
    Orchestrate top level function
    """
    if args['command'] == 'ADD':
        create(args)
    elif args['command'] == 'DEL':
        delete(args)


def create(args):
    """"Handle rkt pod-create event."""
    container_id = args['container_id']
    netns = args['netns']
    interface = args['interface']
    net_name = args['name']
    subnet = args['subnet']

    _log.info('Configuring pod %s' % container_id)
    netns_path = '%s/%s/%s' % (NETNS_ROOT, container_id, netns)

    endpoint = _create_calico_endpoint(container_id=container_id,
                                           netns_path=netns_path,
                                           interface=interface,
                                           subnet=subnet)

    _set_profile_on_endpoint(endpoint=endpoint,
                             profile_name=net_name)

    dump = json.dumps(
        {
            "ip4": {
                "ip": "%s" % endpoint.ipv4_nets.copy().pop()
            }
        })
    _log.info('Dumping info to rkt: %s' % dump)
    print(dump)

    _log.info('Finished Creating pod %s' % container_id)


def delete(args):
    """Cleanup after a pod."""
    container_id = args['container_id']
    net_name = args['name']

    _log.info('Deleting pod %s' % container_id)

    # Remove the profile for the workload.
    _container_remove(hostname=HOSTNAME,
                      orchestrator_id=ORCHESTRATOR_ID,
                      container_id=container_id)

    # Delete profile if only member
    if datastore_client.profile_exists(net_name) and \
       len(datastore_client.get_profile_members(net_name)) < 1:
        try:
            _log.info("Profile %s has no members, removing from datastore" % net_name)
            datastore_client.remove_profile(net_name)
        except:
            _log.error("Cannot remove profile %s: Profile cannot be found." % container_id)
            sys.exit(1)


def _create_calico_endpoint(container_id, netns_path, interface, subnet):
    """
    Configure the Calico interface for a pod.
    Return Endpoint and IP
    """
    _log.info('Configuring Calico networking.')

    try:
        _ = datastore_client.get_endpoint(hostname=HOSTNAME,
                                          orchestrator_id=ORCHESTRATOR_ID,
                                          workload_id=container_id)
    except KeyError:
        # Calico doesn't know about this container.  Continue.
        pass
    else:
        _log.error("This container has already been configured with Calico Networking.")
        sys.exit(1)

    endpoint = _container_add(hostname=HOSTNAME,
                                  orchestrator_id=ORCHESTRATOR_ID,
                                  container_id=container_id,
                                  netns_path=netns_path,
                                  interface=interface,
                                  subnet=subnet)

    _log.info('Finished configuring network interface')
    return endpoint


def _container_add(hostname, orchestrator_id, container_id, netns_path, interface, subnet):
    """
    Add a container to Calico networking
    Return Endpoint object and newly allocated IP
    """
    # Allocate and Assign ip address through datastore_client
    pool, ip = _assign_to_pool(subnet)

    # Create Endpoint object
    try:
        ep = datastore_client.create_endpoint(HOSTNAME, ORCHESTRATOR_ID,
                                              container_id, [ip])
    except AddrFormatError:
        _log.error("This node is not configured for IPv%d. Unassigning IP "
                   "address %s then exiting." % ip.version, ip)
        datastore_client.unassign_address(pool, ip)
        sys.exit(1)

    # Create the veth, move into the container namespace, add the IP and
    # set up the default routes.
    ep.mac = ep.provision_veth(Namespace(netns_path), interface)
    datastore_client.set_endpoint(ep)
    return ep


def _container_remove(hostname, orchestrator_id, container_id):
    """
    Remove the indicated container on this host from Calico networking
    """
    # Find the endpoint ID. We need this to find any ACL rules
    try:
        endpoint = datastore_client.get_endpoint(hostname=hostname,
                                                 orchestrator_id=orchestrator_id,
                                                 workload_id=container_id)
    except KeyError:
        _log.error("Container %s doesn't contain any endpoints" % container_id)
        sys.exit(1)

    # Remove any IP address assignments that this endpoint has
    for net in endpoint.ipv4_nets | endpoint.ipv6_nets:
        assert(net.size == 1)
        datastore_client.unassign_address(None, net.ip)

    # Remove the endpoint
    netns.remove_veth(endpoint.name)

    # Remove the container from the datastore.
    datastore_client.remove_workload(hostname=hostname,
                                     orchestrator_id=orchestrator_id,
                                     workload_id=container_id)

    _log.info("Removed Calico interface from %s" % container_id)


def _set_profile_on_endpoint(endpoint, profile_name):
    """
    Configure the calico profile to the endpoint
    """
    _log.info('Configuring Pod Profile: %s' % profile_name)

    if datastore_client.profile_exists(profile_name):
        _log.info("Profile %s already exists, applying to endpoint." % (profile_name))

    else:
        _log.info("Creating profile %s." % (profile_name))
        datastore_client.create_profile(profile_name)
        # _assign_default_rules(profile_name)

    # Also set the profile for the workload.
    datastore_client.set_profiles_on_endpoint(profile_names=[profile_name],
                                              endpoint_id=endpoint.endpoint_id)


def _assign_default_rules(profile_name):
    """
    Generate a new profile rule list and update the datastore_client
    :param profile_name: The profile to update
    :type profile_name: string
    :return:
    """
    try:
        profile = datastore_client.get_profile(profile_name)
    except:
        _log.error("Could not apply rules. Profile not found: %s, exiting" % profile_name)
        sys.exit(1)

    rules_dict = {
        "id": profile_name,
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
    profile_rules = Rules.from_json(rules_json)

    datastore_client.profile_update_rules(profile)
    _log.info("Finished applying default rules.")


def _assign_to_pool(subnet):
    """
    Take subnet (str), create IP pool in datastore if none exists.
    Allocate next available IP in pool
    return IPPool, IPAddress
    """
    pool = IPPool(subnet)
    version = IPNetwork(subnet).version
    datastore_client.add_ip_pool(version, pool)
    candidate = SequentialAssignment().allocate(pool)
    candidate = IPAddress(candidate)

    _log.info("Using Pool %s" % pool)
    _log.info("Using IP %s" % candidate)

    return pool, candidate


def validate_args(env, conf):
    """
    Validate and itemize environment and stdin args

    ENV =   {
                'CNI_IFNAME': 'eth0',                   req [default: 'eth0']
                'CNI_ARGS': '',                     
                'CNI_COMMAND': 'ADD',                   req
                'CNI_PATH': '.../.../...',
                'CNI_NETNS': 'netns',                   req [default: 'netns']
                'CNI_CONTAINERID': '1234abcd68',        req
            }
    CONF =  {
                "name": "test",                         req
                "type": "calico", 
                "ipam": {
                    "type": "host-local",
                    "subnet": "10.22.0.0/16",           req
                    "routes": [{"dst": "0.0.0.0/0"}],   optional (unsupported)
                    "range-start": ""                   optional (unsupported)
                    "range-end": ""                     optional (unsupported)
                    }
            }
    args = {
                'command': ENV['CNI_COMMAND']
                'interface': ENV['CNI_IFNAME']
                'netns': ENV['CNI_NETNS']
                'name': CONF['name']
                'subnet': CONF['ipam']['subnet']
    }
    """
    _log.debug('Environment: %s' % env)
    _log.debug('Config: %s' % conf)

    args = dict()

    # ENV
    try:
        args['command'] = env['CNI_COMMAND']
    except KeyError:
        _log.error('No CNI_COMMAND in Environment')
        sys.exit(1)
    else:
        if args['command'] not in ["ADD", "DEL"]:
            _log.error('CNI_COMMAND \'%s\' not recognized' % args['command'])

    try:
        args['container_id'] = env['CNI_CONTAINERID']
    except KeyError:
        _log.error('No CNI_CONTAINERID in Environment')
        sys.exit(1)

    try:
        args['interface'] = env['CNI_IFNAME']
    except KeyError:
        _log.exception(
            'No CNI_IFNAME in Environment, using interface \'eth0\'')
        args['interface'] = 'eth0'

    try:
        args['netns'] = env['CNI_NETNS']
    except KeyError:
        _log.exception('No CNI_NETNS in Environment, using \'netns\'')
        args['netns'] = 'netns'

    # CONF
    try:
        args['name'] = conf['name']
    except KeyError:
        _log.error('No Name in Network Config')
        sys.exit(1)

    try:
        args['subnet'] = conf['ipam']['subnet']
    except KeyError:
        _log.error('No Subnet in Network Config')
        sys.exit(1)

    _log.debug('Validated Args: %s' % args)
    return args


if __name__ == '__main__':
    # Setup logger
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
    hdlr = logging.FileHandler(filename=LOG_DIR+'/calico-rkt.log')
    formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
    hdlr.setFormatter(formatter)
    _log.addHandler(hdlr)
    _log.setLevel(logging.INFO)

    # Environment
    env = os.environ.copy()

    # STDIN args
    conf_raw = ''.join(sys.stdin.readlines()).replace('\n', '')
    conf_json = json.loads(conf_raw).copy()

    # Scrub args
    args = validate_args(env, conf_json)

    # Call plugin
    calico_rkt(args)
