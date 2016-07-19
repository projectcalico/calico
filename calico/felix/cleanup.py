# -*- coding: utf-8 -*-
# Copyright (c) 2016 Tigera, Inc. All rights reserved.
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

from collections import defaultdict
import logging
import re
from subprocess import check_output, check_call, call

from calico.felix.frules import FELIX_PREFIX, POSTROUTING_LOCAL_NAT_FRAGMENT
from calico.felix.ipsets import FELIX_PFX
from calico.felix.masq import MASQ_RULE_FRAGMENT

_log = logging.getLogger(__name__)

JUMP_RULE_RE = r'-A ((?!%s)\w+ .*-j %s\w+.*)' % (FELIX_PREFIX, FELIX_PREFIX)
"""Regex to match top-level jump rules from, for example, INPUT to
felix-INPUT."""

IPSET_NAME_RE = r"^Name: (%s.*)" % FELIX_PFX


def main():
    clean_up_iptables("iptables", "iptables-save")
    clean_up_iptables("ip6tables", "ip6tables-save")
    clean_up_ipsets()


def clean_up_iptables(iptables_cmd, iptables_save_cmd):
    # We can't delete chains until they're unreferenced.  First, remove felix
    # jump rules from kernel chains.
    ipt_lines = check_output([iptables_save_cmd]).splitlines()
    table = None
    for line in ipt_lines:
        # The start of each table is signified with a line of the form
        # "*tablename\n".
        m = re.match(r"^\*(\S+)", line)
        if m:
            # Start of a new table, save off the name.
            table = m.group(1)
        m = re.match(JUMP_RULE_RE, line)
        if m:
            # Found a jump rule, convert it to a delete command and execute.
            print "Removing rule from kernel chain: %s" % line
            assert table is not None, ("Jump rule before table name in "
                                       "iptables-save output?")
            check_call(iptables_cmd + " -t %s -D %s" % (table, m.group(1)),
                       shell=True)

    # Remove special-case rules :-(
    call(iptables_cmd + " -D %s" % POSTROUTING_LOCAL_NAT_FRAGMENT,
         shell=True, stderr=open("/dev/null", "w"))
    call(iptables_cmd + " -D %s" % MASQ_RULE_FRAGMENT,
         shell=True, stderr=open("/dev/null", "w"))

    # Find all our chains.
    our_chains_by_table = defaultdict(set)
    table = None
    for line in ipt_lines:
        if line.startswith("*"):
            table = line[1:]
        elif line.startswith(":"):
            chain = line[1:line.index(" ")]
            if chain.startswith(FELIX_PREFIX):
                our_chains_by_table[table].add(chain)

    # Flush them all to remove dependencies.
    for table, chains in our_chains_by_table.iteritems():
        for chain in chains:
            print "Flushing chain %s" % chain
            check_call([iptables_cmd, "-t", table, "-F", chain])

    # Then delete them.
    for table, chains in our_chains_by_table.iteritems():
        for chain in chains:
            print "Deleting chain %s" % chain
            check_call([iptables_cmd, "-t", table, "-X", chain])


def clean_up_ipsets():
    # Parse ipset list output to find the ipsets.
    ipsets = set()
    for line in check_output(["ipset", "list"]).splitlines():
        m = re.match(IPSET_NAME_RE, line)
        if m:
            ipsets.add(m.group(1))
    # Then delete them.
    for ipset in ipsets:
        print "Deleting ipset %s" % ipset
        call(["ipset", "destroy", ipset])


if __name__ == "__main__":
    main()
