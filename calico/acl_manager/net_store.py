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

log = logging.getLogger(__name__)

    
class NetworkStore(object):

    def __init__(self):
        """
        Create a new Network Store.
        
        None of the Network Store's methods are thread-safe.
        """
        log.debug("Creating Network Store object")
        self.groups = []
        self.group_members = {}
        self.group_rules = {}
        self.rule_processors = []
        
    def get_groups(self):
        """
        Returns the list of group UUIDs known to the Network Store.
        """
        # Long term this method will be retired and replaced with a mechanism
        # for calculating the set of groups affected by a change and only
        # recalculating those.  In this release, efficiency is not a concern,
        # so just recalculate everything whenever anything changes.
        return self.groups
    
    def get_group_members(self, group_uuid):
        """
        Returns a dictionary mapping the group's members' UUIDs to the IP
        addresses that endpoint has.
        
        This method is safe to call even for non-existent groups, in which case
        it will return an empty dictionary.
        """
        if group_uuid in self.group_members:
            assert len(self.group_members[group_uuid]) != 0
            return self.group_members[group_uuid]
        else:
            # It is useful to allow this to be called for non-existent groups
            # because those groups may still be referred to by other groups'
            # rules.
            log.debug("Group %s contains no members" % group_uuid)
            return {}
    
    def get_group_rules(self, group_uuid):
        """
        Returns a rules object for the group, as specified on the Calico
        Network API.  The group must exist (=== its UUID is returned by
        get_groups()).
        """
        assert group_uuid in self.group_rules
        assert group_uuid in self.group_members
        return self.group_rules[group_uuid]
        
    def add_processor(self, rule_processor):
        """
        Associate a Rule Processor with a Network Store.  The Network Store
        will call into the Rule Processor every time the network state changes.
        """
        self.rule_processors.append(rule_processor)
        
    def update_group(self, group_uuid, members, rules):
        """
        Update the Network information for a group.  Updating a group to have
        no members deletes the group.
        
        - group_uuid: The UUID of the group to update
        - members: A dictionary of endpoint_uuid => [that endpoint's IPs]
        - rules: A rules object, as defined on the Calico Network API
        """
        if (len(members) == 0) and (group_uuid in self.group_members):
            # Delete the group because it has no members.
            log.info("Removing empty group %s" % group_uuid)
            self.groups.remove(group_uuid)
            del self.group_members[group_uuid]
            del self.group_rules[group_uuid]
        elif len(members) > 0:
            # New group (with members!).
            if group_uuid not in self.group_members:
                log.info("Storing new group %s" % group_uuid)
                self.groups.append(group_uuid)
            
            self.group_members[group_uuid] = members
            self.group_rules[group_uuid] = rules
            
        # Now reprocess all the group information.  In the current
        # implementation no indication of what has changed is provided.
        for proc in self.rule_processors:
            proc.recalc_rules()