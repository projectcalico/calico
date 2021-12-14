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

from networking_calico.common import config as calico_config
from networking_calico.compat import IP_PROTOCOL_MAP
from networking_calico.compat import log
from networking_calico import datamodel_v3
from networking_calico.plugins.ml2.drivers.calico.syncer import ResourceSyncer

LOG = log.getLogger(__name__)

# Each OpenStack security group is mapped to a Calico NetworkPolicy.  A VM's
# security group membership is represented by the VM having a label for each
# security group that it belongs to; thus the selector
# 'has(<security-group-label>)' represents the VMs that belong to that security
# group.
#
# The label for each security group is 'sg.projectcalico.org/openstack-'
# followed by the security group ID, and the name of the NetworkPolicy for each
# security group is 'ossg.default.'  followed by the security group ID.
SG_LABEL_PREFIX = 'sg.projectcalico.org/openstack-'
SG_NAME_LABEL_PREFIX = 'sg-name.projectcalico.org/openstack-'
SG_NAME_MAX_LENGTH = (datamodel_v3.SANITIZE_LABEL_MAX_LENGTH -
                      len(SG_NAME_LABEL_PREFIX))
SG_NAME_PREFIX = 'ossg.default.'


class PolicySyncer(ResourceSyncer):

    def __init__(self, db, txn_from_context):
        super(PolicySyncer, self).__init__(db,
                                           txn_from_context,
                                           "NetworkPolicy")
        self.region_string = calico_config.get_region_string()
        self.namespace = datamodel_v3.get_namespace(self.region_string)

    def delete_legacy_etcd_data(self):
        if self.namespace != datamodel_v3.NO_REGION_NAMESPACE:
            datamodel_v3.delete_legacy(self.resource_kind, SG_NAME_PREFIX)

    def get_all_from_etcd(self):
        results = []
        for r in datamodel_v3.get_all(self.resource_kind, self.namespace):
            name, _, _ = r
            if name.startswith(SG_NAME_PREFIX):
                results.append(r)
        return results

    def create_in_etcd(self, name, spec):
        return datamodel_v3.put(self.resource_kind,
                                self.namespace,
                                name,
                                spec,
                                mod_revision=0)

    def update_in_etcd(self, name, spec, mod_revision=None):
        return datamodel_v3.put(self.resource_kind,
                                self.namespace,
                                name,
                                spec,
                                mod_revision=mod_revision)

    def delete_from_etcd(self, name, mod_revision):
        return datamodel_v3.delete(self.resource_kind,
                                   self.namespace,
                                   name,
                                   mod_revision=mod_revision)

    def get_all_from_neutron(self, context):
        return dict((SG_NAME_PREFIX + sg['id'], sg)
                    for sg in self.db.get_security_groups(context))

    def neutron_to_etcd_write_data(self, sg, context, reread=False):
        if reread:
            # We don't need to reread the SG row itself here, because we don't
            # use any information from it, apart from its ID as a key for the
            # following rules.
            pass
        rules = self.db.get_security_group_rules(
            context,
            filters={'security_group_id': [sg['id']]}
        )
        return policy_spec(sg['id'], rules)

    def write_sgs_to_etcd(self, sgids, context):
        rules = self.db.get_security_group_rules(
            context, filters={'security_group_id': sgids}
        )
        for sgid in sgids:
            self.update_in_etcd(SG_NAME_PREFIX + sgid,
                                policy_spec(sgid, rules))


def policy_spec(sgid, rules):
    """Generate JSON NetworkPolicySpec for the given security group."""

    # <rules> can include those for several security groups.  Pick out the
    # rules for the security group that we are translating right now.
    sg_rules = (r for r in rules if r['security_group_id'] == sgid)

    # Split the rules based on direction, and map to Calico form.
    inbound_rules = []
    outbound_rules = []
    for rule in sg_rules:
        if rule['direction'] == 'ingress':
            inbound_rules.append(_neutron_rule_to_etcd_rule(rule))
        else:
            outbound_rules.append(_neutron_rule_to_etcd_rule(rule))

    return {
        'ingress': inbound_rules,
        'egress': outbound_rules,
        'selector': 'has(%s)' % (SG_LABEL_PREFIX + sgid),
    }


def _neutron_rule_to_etcd_rule(rule):
    """_neutron_rule_to_etcd_rule

    Translate a single Neutron rule dict to a single dict in our
    etcd format.
    """
    ethertype = rule['ethertype']
    etcd_rule = {'action': 'Allow'}

    # Map the ethertype field from Neutron to etcd format.
    etcd_rule['ipVersion'] = {'IPv4': 4,
                              'IPv6': 6}[ethertype]

    # Map the protocol field from Neutron to etcd format.
    #
    # Per https://docs.openstack.org/api-ref/network/v2/
    # ?expanded=create-security-group-rule-detail#
    # security-group-rules-security-group-rules:
    #
    # "The IP protocol can be represented by a string, an integer, or
    # null. Valid string or integer values are any or 0, ah or 51,
    # dccp or 33, egp or 8, esp or 50, gre or 47, icmp or 1, icmpv6 or
    # 58, igmp or 2, ipip or 4, ipv6-encap or 41, ipv6-frag or 44,
    # ipv6-icmp or 58, ipv6-nonxt or 59, ipv6-opts or 60, ipv6-route
    # or 43, ospf or 89, pgm or 113, rsvp or 46, sctp or 132, tcp or
    # 6, udp or 17, udplite or 136, vrrp or 112. Additionally, any
    # integer value between [0-255] is also valid. The string any (or
    # integer 0) means all IP protocols. See the constants in
    # neutron_lib.constants for the most up-to-date list of supported
    # strings."
    #
    # In addition we have previously supported -1 for any, and 'icmp'
    # to mean 'icmpv6' when the ethertype is IPv6; so we also retain
    # those for back-compatibility.
    if rule['protocol'] is None or rule['protocol'] in [-1, 0, 'any']:
        # In the Calico data model, 'any' is represented by omitting
        # the 'protocol' field.
        pass
    elif rule['protocol'] == 'ipv6-icmp':
        etcd_rule['protocol'] = 'ICMPv6'
    elif rule['protocol'] == 'icmp':
        etcd_rule['protocol'] = {'IPv4': 'ICMP',
                                 'IPv6': 'ICMPv6'}[ethertype]
    elif isinstance(rule['protocol'], int):
        etcd_rule['protocol'] = rule['protocol']
    elif rule['protocol'] in IP_PROTOCOL_MAP:
        etcd_rule['protocol'] = IP_PROTOCOL_MAP[rule['protocol']]
    else:
        etcd_rule['protocol'] = rule['protocol'].upper()

    port_spec = None
    if rule['protocol'] == 'icmp' or rule['protocol'] == 'ipv6-icmp':
        # OpenStack stashes the ICMP match criteria in
        # port_range_min/max.
        icmp_fields = {}
        icmp_type = rule['port_range_min']
        if icmp_type is not None and icmp_type != -1:
            icmp_fields['type'] = icmp_type
        icmp_code = rule['port_range_max']
        if icmp_code is not None and icmp_code != -1:
            icmp_fields['code'] = icmp_code
        if icmp_fields:
            etcd_rule['icmp'] = icmp_fields
    else:
        # src/dst_ports is a list in which each entry can be a
        # single number, or a string describing a port range.
        if rule['port_range_min'] == -1:
            port_spec = None
        elif rule['port_range_min'] == rule['port_range_max']:
            if rule['port_range_min'] is not None:
                port_spec = [rule['port_range_min']]
        else:
            port_spec = ['%s:%s' % (rule['port_range_min'],
                                    rule['port_range_max'])]

    entity_rule = {}
    if rule['remote_group_id'] is not None:
        entity_rule['selector'] = 'has(%s)' % (SG_LABEL_PREFIX +
                                               rule['remote_group_id'])
    if rule['remote_ip_prefix'] is not None:
        entity_rule['nets'] = [rule['remote_ip_prefix']]
    LOG.debug("=> Entity rule %s" % entity_rule)

    # Store in source or destination field of the overall rule.
    if entity_rule:
        if rule['direction'] == 'ingress':
            etcd_rule['source'] = entity_rule
            if port_spec is not None:
                etcd_rule['destination'] = {'ports': port_spec}
        else:
            if port_spec is not None:
                entity_rule['ports'] = port_spec
            etcd_rule['destination'] = entity_rule

    LOG.debug("=> %s Calico rule %s" % (rule['direction'], etcd_rule))

    return etcd_rule
