# -*- coding: utf-8 -*-
# Copyright (c) 2018 Tigera, Inc. All rights reserved.
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

from neutron.db import models_v2
try:
    from neutron.db.models.l3 import FloatingIP
except ImportError:
    # Ocata and earlier.
    from neutron.db.l3_db import FloatingIP

from networking_calico.compat import log
from networking_calico.compat import n_exc
from networking_calico import datamodel_v3
from networking_calico.plugins.ml2.drivers.calico.policy import \
    SG_LABEL_PREFIX
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceGone
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceSyncer


LOG = log.getLogger(__name__)


class WorkloadEndpointSyncer(ResourceSyncer):

    def __init__(self, db, txn_from_context, policy_syncer):
        super(WorkloadEndpointSyncer, self).__init__(db,
                                                     txn_from_context,
                                                     "WorkloadEndpoint")
        self.policy_syncer = policy_syncer

    # The following methods differ from those for other resources because for
    # endpoints we need to read, compare and write labels and annotations as
    # well as spec.

    def get_all_from_etcd(self):
        return datamodel_v3.get_all(self.resource_kind,
                                    with_labels_and_annotations=True)

    def etcd_write_data_matches_existing(self, write_data, existing):
        rspec, rlabels, rannotations = existing
        wspec, wlabels, wannotations = write_data
        return (rspec == wspec and
                rlabels == wlabels and
                rannotations == wannotations)

    def create_in_etcd(self, name, write_data):
        spec, labels, annotations = write_data
        return datamodel_v3.put(self.resource_kind,
                                name,
                                spec,
                                labels=labels,
                                annotations=annotations,
                                mod_revision=0)

    def update_in_etcd(self, name, write_data, mod_revision=None):
        spec, labels, annotations = write_data
        return datamodel_v3.put(self.resource_kind,
                                name,
                                spec,
                                labels=labels,
                                annotations=annotations,
                                mod_revision=mod_revision)

    def delete_from_etcd(self, name, mod_revision):
        return datamodel_v3.delete(self.resource_kind, name,
                                   mod_revision=mod_revision)

    def get_all_from_neutron(self, context):
        # TODO(lukasa): We could reduce the amount of data we load from Neutron
        # here by filtering in the get_ports call.
        return dict((endpoint_name(port), port)
                    for port in self.db.get_ports(context)
                    if _port_is_endpoint_port(port))

    def neutron_to_etcd_write_data(self, port, context, reread=False):
        if reread:
            try:
                port = self.db.get_port(context, port['id'])
            except n_exc.PortNotFound:
                raise ResourceGone()
        port = self.add_extra_port_information(context, port)
        return (endpoint_spec(port),
                endpoint_labels(port),
                endpoint_annotations(port))

    def write_endpoint(self, port, context):
        # Reread the current port. This protects against concurrent writes
        # breaking our state.
        port = self.db.get_port(context, port['id'])

        # Fill out other information we need on the port.
        port = self.add_extra_port_information(context, port)

        # Write the security policies for this port.
        self.policy_syncer.write_sgs_to_etcd(port['security_groups'], context)

        # Implementation note: we could arguably avoid holding the transaction
        # for this length and instead release it here, then use atomic CAS. The
        # problem there is that we potentially have to repeatedly respin and
        # regain the transaction. Let's not do that for now, and performance
        # test to see if it's a problem later.
        datamodel_v3.put("WorkloadEndpoint",
                         endpoint_name(port),
                         endpoint_spec(port),
                         labels=endpoint_labels(port),
                         annotations=endpoint_annotations(port))

    def delete_endpoint(self, port):
        datamodel_v3.delete("WorkloadEndpoint", endpoint_name(port))

    def add_port_interface_name(self, port):
        port['interface_name'] = 'tap' + port['id'][:11]

    def get_security_groups_for_port(self, context, port):
        """Checks which security groups apply for a given port.

        Frustratingly, the port dict provided to us when we call get_port may
        actually be out of date, and I don't know why. This change ensures that
        we get the most recent information.
        """
        filters = {'port_id': [port['id']]}
        bindings = self.db._get_port_security_group_bindings(
            context, filters=filters
        )
        return [binding['security_group_id'] for binding in bindings]

    def get_fixed_ips_for_port(self, context, port):
        """Obtains a complete list of fixed IPs for a port.

        Much like with security groups, for some insane reason we're given an
        out of date port dictionary when we call get_port. This forces an
        explicit query of the IPAllocation table to get the right data out of
        Neutron.
        """
        return [
            {'subnet_id': ip['subnet_id'], 'ip_address': ip['ip_address']}
            for ip in context.session.query(
                models_v2.IPAllocation
            ).filter_by(
                port_id=port['id']
            )
        ]

    def get_floating_ips_for_port(self, context, port):
        """Obtains a list of floating IPs for a port."""
        return [
            {'int_ip': ip['fixed_ip_address'],
             'ext_ip': ip['floating_ip_address']}
            for ip in context.session.query(
                FloatingIP
            ).filter_by(
                fixed_port_id=port['id']
            )
        ]

    def add_extra_port_information(self, context, port):
        """add_extra_port_information

        Gets extra information for a port that is needed before sending it to
        etcd.
        """
        port['fixed_ips'] = self.get_fixed_ips_for_port(
            context, port
        )
        port['floating_ips'] = self.get_floating_ips_for_port(
            context, port
        )
        port['security_groups'] = self.get_security_groups_for_port(
            context, port
        )
        self.add_port_gateways(port, context)
        self.add_port_interface_name(port)
        return port

    def add_port_gateways(self, port, context):
        """add_port_gateways

        Determine the gateway IP addresses for a given port's IP addresses, and
        adds them to the port dict.

        This method assumes it's being called from within a database
        transaction and does not take out another one.
        """
        for ip in port['fixed_ips']:
            subnet = self.db.get_subnet(context, ip['subnet_id'])
            ip['gateway'] = subnet['gateway_ip']


def endpoint_name(port):
    def escape_dashes(s):
        return s.replace("-", "--")
    return "%s-openstack-%s-%s" % (
        escape_dashes(port['binding:host_id']),
        escape_dashes(port['device_id']),
        escape_dashes(port['id']),
    )


def endpoint_labels(port):
    labels = dict((SG_LABEL_PREFIX + sg_id, '')
                  for sg_id in port['security_groups'])
    labels['projectcalico.org/namespace'] = 'openstack'
    labels['projectcalico.org/orchestrator'] = 'openstack'
    return labels


# Represent a Neutron port as a Calico v3 WorkloadEndpoint spec.
def endpoint_spec(port):
    """endpoint_spec

    Generate JSON WorkloadEndpointSpec for the given Neutron port.
    """

    # Construct the simpler spec data.
    data = {
        'orchestrator': 'openstack',
        'workload': port['device_id'],
        'node': port['binding:host_id'],
        'endpoint': port['id'],
        'interfaceName': port['interface_name'],
        'mac': port['mac_address'],
    }

    # Collect IPv4 and IPv6 addresses.  On the way, also set the corresponding
    # gateway fields.  If there is more than one IPv4 or IPv6 gateway, the last
    # one (in port['fixed_ips']) wins.
    ip_nets = []
    for ip in port['fixed_ips']:
        if ':' in ip['ip_address']:
            ip_nets.append(ip['ip_address'] + '/128')
            if ip['gateway'] is not None:
                data['ipv6Gateway'] = ip['gateway']
        else:
            ip_nets.append(ip['ip_address'] + '/32')
            if ip['gateway'] is not None:
                data['ipv4Gateway'] = ip['gateway']
    data['ipNetworks'] = ip_nets

    ip_nats = []
    for ip in port['floating_ips']:
        ip_nats.append({
            'internalIP': ip['int_ip'],
            'externalIP': ip['ext_ip'],
        })
    if ip_nats:
        data['ipNATs'] = ip_nats

    # Return that data.
    return data


def endpoint_annotations(port):
    annotations = {datamodel_v3.ANN_KEY_NETWORK_ID: port['network_id']}

    # If the port has a DNS assignment, represent that as an FQDN annotation.
    dns_assignment = port.get('dns_assignment')
    if dns_assignment:
        # Note: the Neutron server generates a list of assignment entries, one
        # for each fixed IP, but all with the same FQDN, for slightly
        # historical reasons.  We're fine getting the FQDN from the first
        # entry.
        annotations[datamodel_v3.ANN_KEY_FQDN] = dns_assignment[0]['fqdn']

    return annotations


def _port_is_endpoint_port(port):
    # Return True if port is a VM port.
    if port['device_owner'].startswith('compute:'):
        return True

    # Also return True if port is for a Kuryr container.
    if port['device_owner'].startswith('kuryr:container'):
        return True

    # Otherwise log and return False.
    LOG.debug("Not a VM port: %s" % port)
    return False
