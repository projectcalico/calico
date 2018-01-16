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
from docker_host import DockerHost, CHECKOUT_DIR
from utils import get_ip, ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL

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
                ip_env = "-e IP=%s" % rr.ip
                rr.execute("docker load --input /code/routereflector.tar")

                # Check which type of etcd is being run, then invoke the
                # suggested curl command to add the RR entry to etcd.
                #
                # See https://github.com/projectcalico/calico-bird/tree/feature-ipinip/build_routereflector
                # for details.
		rr_container_name = os.getenv("RR_CONTAINER_NAME", "calico/routereflector:latest")
                if os.getenv("ETCD_SCHEME", None) == "https":
                    # Etcd is running with SSL/TLS, pass the key values
                    rr.execute("docker run --privileged --net=host -d "
                               "--name rr %s "
                               "-e ETCD_ENDPOINTS=https://%s:2379 "
                               "-e ETCD_CA_CERT_FILE=%s "
                               "-e ETCD_CERT_FILE=%s "
                               "-e ETCD_KEY_FILE=%s "
                               "-v %s/certs:%s/certs "
                               "%s" %
                               (ip_env, ETCD_HOSTNAME_SSL, ETCD_CA, ETCD_CERT,
                                ETCD_KEY, CHECKOUT_DIR, CHECKOUT_DIR, rr_container_name))
                    rr.execute(r'curl --cacert %s --cert %s --key %s '
                               r'-L https://%s:2379/v2/keys/calico/bgp/v1/rr_v4/%s '
                               r'-XPUT -d value="{'
                                 r'\"ip\":\"%s\",'
                                 r'\"cluster_id\":\"%s\"'
                               r'}"' % (ETCD_CA, ETCD_CERT, ETCD_KEY,
                                        ETCD_HOSTNAME_SSL, rr.ip, rr.ip,
                                        cluster_id))

                else:
                    rr.execute("docker run --privileged --net=host -d "
                           "--name rr %s "
                           "-e ETCD_ENDPOINTS=http://%s:2379 "
                           "%s" % (ip_env, get_ip(), rr_container_name))
                    rr.execute(r'curl -L http://%s:2379/v2/keys/calico/bgp/v1/rr_v4/%s '
                               r'-XPUT -d value="{'
                                 r'\"ip\":\"%s\",'
                                 r'\"cluster_id\":\"%s\"'
                               r'}"' % (get_ip(), rr.ip, rr.ip, cluster_id))
                # Store the redundancy group.
                redundancy_group.append(rr)
            self.redundancy_groups.append(redundancy_group)

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
                    self.pop_and_cleanup_route_reflector(rg)
                except KeyboardInterrupt:
                    raise
                except Exception:
                    pass

    def pop_and_cleanup_route_reflector(self, redundancy_group):
        """
        Pop a route reflector off the stack and clean it up.
        """
        rr = redundancy_group.pop()
        rr.cleanup()

    def get_redundancy_group(self):
        """
        Return a redundancy group to use.  This iterates through redundancy
        groups each invocation.
        :return: A list of RRs in the redundancy group.
        """
        rg = self.redundancy_groups.pop(0)
        self.redundancy_groups.append(rg)
        return rg
