# Copyright 2015 Metaswitch Networks
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

import copy
import re

from neutron.agent.linux import dhcp


class DnsmasqRouted(dhcp.Dnsmasq):
    """Dnsmasq DHCP driver for routed virtual interfaces."""

    def _build_cmdline_callback(self, pid_file):
        cmd = super(DnsmasqRouted, self)._build_cmdline_callback(pid_file)

        # Replace 'static' by 'static,off-link' in all IPv6
        # --dhcp-range options.
        prog = re.compile('(--dhcp-range=set:[^,]+,[0-9a-f:]+),static,(.*)')
        for option in copy.copy(cmd):
            m = prog.match(option)
            if m:
                cmd.remove(option)
                cmd.append(m.group(1) + ',static,off-link,' + m.group(2))

        # Add '--enable-ra'.
        cmd.append('--enable-ra')

        return cmd
