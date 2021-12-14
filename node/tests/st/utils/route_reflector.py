# Copyright (c) 2015-2016 Tigera, Inc. All rights reserved.
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

import os
from docker_host import DockerHost

from netaddr import IPAddress

class RouteReflectorCluster(object):
    """
    Encapsulate the setting up and tearing down of a route reflector cluster.
    """

    def __init__(self, num_in_redundancy_group, num_redundancy_groups):
        """
        :param num_rrs: The number of route reflectors in the cluster.
        """
        self.num_in_redundancy_group = num_in_redundancy_group
        self.num_redundancy_groups = num_redundancy_groups
        self.redundancy_groups = []

    def __enter__(self):
        """
        Set up the route reflector clusters when entering context.
        :return: self.
        """
        # Create the route reflector hosts, grouped by redundancy.
        for ii in range(self.num_redundancy_groups):
            cluster_id = str(IPAddress(0xFF000001 + ii))
            redundancy_group = []
            for jj in range(self.num_in_redundancy_group):
                rr = DockerHost('RR.%d.%d' % (ii, jj), start_calico=False)
                rr.add_resource({
                    'apiVersion': 'projectcalico.org/v3',
                    'kind': 'Node',
                    'metadata': {
                        'name': rr.get_hostname(),
                        'labels': {
                            'routeReflectorClusterID': cluster_id,
                        },
                    },
                    'spec': {
                        'bgp': {
                            'routeReflectorClusterID': cluster_id,
                        },
                    },
                })
                rr.start_calico_node()

                # Store the redundancy group.
                redundancy_group.append(rr)
            self.redundancy_groups.append(redundancy_group)

        # If there is more than one of them, configure full mesh
        # peering between the route reflectors.
        if self.num_redundancy_groups * self.num_in_redundancy_group > 1:
            rr.add_resource({
                'apiVersion': 'projectcalico.org/v3',
                'kind': 'BGPPeer',
                'metadata': {
                    'name': 'rr-mesh',
                },
                'spec': {
                    'nodeSelector': 'has(routeReflectorClusterID)',
                    'peerSelector': 'has(routeReflectorClusterID)',
                },
            })

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """
        Tear down the route reflector hosts when exiting context.
        :return: None
        """
        # Try to clean up what we can before exiting.
        for rg in self.redundancy_groups:
            while rg:
                try:
                    self.pop_and_cleanup_route_reflector(rg, log_extra_diags=bool(exc_type))
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

    def pop_and_cleanup_route_reflector(self, redundancy_group, log_extra_diags=False):
        """
        Pop a route reflector off the stack and clean it up.
        """
        rr = redundancy_group.pop()
        rr.cleanup(log_extra_diags=log_extra_diags)

    def get_redundancy_group(self):
        """
        Return a redundancy group to use.  This iterates through redundancy
        groups each invocation.
        :return: A list of RRs in the redundancy group.
        """
        rg = self.redundancy_groups.pop(0)
        self.redundancy_groups.append(rg)
        return rg
