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

# This is an initial (inefficient) implementation.  It's likely to be rewritten
# completely once a full analysis of the performance requirements is complete.

# Additionally it's currently limited to a single security group per endpoint,
# and the defaults must be deny.  These limitations will be removed once we've
# determined the best method to deal with conflicting defaults.
class RuleProcessor(object):
    def __init__(self, acl_store, network_store):
        self.acl_store = acl_store
        self.network_store = network_store

    def recalc_rules(self):
        log.info("Recalculating ACLs")
        ns = self.network_store
        
        # First get the group and endpoint information.
        group_members = {group: ns.get_group_members(group) for
                                                    (group) in ns.get_groups()}
        endpoint_groups = defaultdict(list)
        for group, endpoints in group_members.iteritems():
            for endpoint_uuid in endpoints.keys():
                endpoint_groups[endpoint_uuid].append(group)
        
        # Now build the ACLs for each endpoint.
        for endpoint_uuid, groups in endpoint_groups.iteritems():
            if endpoint_uuid == "": continue
            acls = {}
            
            group = groups[0]
            if len(groups) > 1:
                log.warning("%s Security groups other than 1st being ignored" %
                            endpoint_uuid)
            
            rules = ns.get_group_rules(group)
            for (ip_type, ip_match, ip_len) in (("v4", ".", 32),
                                                ("v6", ":", 128)):
                log.debug("Calculating IP%s ACLs for %s" %
                                                      (ip_type, endpoint_uuid))
                ip_acls = {}

                assert rules["inbound_default"] == "deny"
                assert rules["outbound_default"] == "deny"
                ip_acls["inbound_default"] = "deny"
                ip_acls["outbound_default"] = "deny"
                
                # Set up the inbound and outbound ACLs.
                for bound in ("in", "out"):
                    ip_acls["%sbound" % bound] = []
                    for rule in rules["%sbound" % bound]:                   
                        if rule["group"] is not None:
                            # Process group rule.  The group id must be
                            # translated into a list of IPs in that group, so
                            # each rule may form many ACLs.
                            assert (rule["cidr"] is None)
                            acl = deepcopy(rule)
                            acl["group"] = None
                            group_ips = [item for sublist in group_members[rule["group"]].values() for item in sublist]
                            for target_ep_ip in (x for x in group_ips if (ip_match in x)):
                                acl["cidr"] = "%s/%d" % (target_ep_ip, ip_len)
                                ip_acls["%sbound" % bound].append(deepcopy(acl))
                        elif (rule["cidr"] is not None) and (ip_match in rule["cidr"]):
                            # Process cidr rule.  These don't need any
                            # translation and map onto a single ACL.
                            ip_acls["%sbound" % bound].append(rule)
                        else:
                            log.debug("Skipping empty / wrong IP typerule %s" %
                                      rule)

                acls[ip_type] = ip_acls
        
            self.acl_store.update_endpoint_rules(endpoint_uuid, acls)