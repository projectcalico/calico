# Copyright (c) 2014 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import logging
from collections import defaultdict
from copy import deepcopy

log = logging.getLogger(__name__)


class RuleProcessor(object):
    def __init__(self, acl_store, network_store):
        self.acl_store = acl_store
        self.network_store = network_store

    def recalc_rules(self):
        log.info("Recalculating ACLs")
        ns = self.network_store

        # First get the group and endpoint information.  Use defaultdicts for
        # both of these to support groups with no endpoints.
        group_members = defaultdict(
            dict,
            ((group, ns.get_group_members(group)) for group in ns.get_groups())
        )
        endpoint_groups = defaultdict(list)
        for group, endpoints in group_members.iteritems():
            for endpoint_uuid in endpoints.keys():
                endpoint_groups[endpoint_uuid].append(group)

        # Now build the ACLs for each endpoint.
        for endpoint_uuid, groups in endpoint_groups.iteritems():
            if endpoint_uuid == "": continue
            acls = {}

            for (ip_type, ip_match, ip_len) in (("v4", ".", 32),
                                                ("v6", ":", 128)):
                log.debug("Calculating IP%s ACLs for %s" %
                                                      (ip_type, endpoint_uuid))
                ip_acls = {"inbound_default": "deny",
                           "outbound_default": "deny"}

                # Set up the inbound and outbound ACLs.
                for bound in ("in", "out"):
                    wip_acls = []

                    # Walk through the list of groups the endpoint is in, and
                    # add the rules for that group into the current ACL list.
                    for group in groups:
                        rules = ns.get_group_rules(group)

                        # The defaults for inbound and outbound traffic  must
                        # both be deny.  There's no universally correct way to
                        # resolve the default for an endpoint which is in
                        # multiple security groups if those defaults are
                        # allowed to differ.  Openstack's default is 'deny', so
                        # assert on that.
                        assert rules["inbound_default"] == "deny"
                        assert rules["outbound_default"] == "deny"

                        for rule in rules["%sbound" % bound]:
                            if rule["group"] is not None:
                                # Process group rule.  The group id must be
                                # translated into a list of IPs in that group,
                                # so each rule may form many ACLs.
                                assert rule["cidr"] is None
                                acl = deepcopy(rule)
                                acl["group"] = None
                                group_ips = [
                                    item for sublist in
                                    group_members[rule["group"]].values()
                                    for item in sublist]
                                for target_ep_ip in (
                                    x for x in group_ips if ip_match in x):
                                    acl["cidr"] = "%s/%d" % (target_ep_ip,
                                                             ip_len)
                                    wip_acls.append(deepcopy(acl))
                            elif ((rule["cidr"] is not None) and
                                (ip_match in rule["cidr"])):
                                # Process cidr rule.  These don't need any
                                # translation and map onto a single ACL.
                                wip_acls.append(rule)
                            else:
                                log.debug("Skip empty/wrong IP type rule %s" %
                                          rule)
                    ip_acls["%sbound" % bound] = wip_acls
                acls[ip_type] = ip_acls

            self.acl_store.update_endpoint_rules(endpoint_uuid, acls)
