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
import re
from subprocess import CalledProcessError

from netaddr import IPAddress, IPNetwork

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost

"""
Test the calicoctl container <CONTAINER> ip add/remove commands.

Tests the edge cases that aren't already covered by the mainline tests.
"""

def get_ip_from_container_add_output(output):
    """
    Return the IP address from the output message of calicoctl container add
    """
    ip_re = re.compile("IP (.*) added to .*")
    ip_match = ip_re.match(output.strip())
    return IPAddress(ip_match.group(1))

class TestManagePools(TestBase):
    """
    Test management of IP pools and interactions with IPAM.
    """
    def test_delete_pool(self):
        """
        Test deletion of a pool prevents automatic IP assignment from that
        pool.
        """
        with DockerHost('host') as host:
            # Create a couple of workloads with IPs assigned from the default
            # pool.
            default_cidr = IPNetwork("192.168.0.0/16")
            new_cidr = IPNetwork("192.169.0.0/26")
            workload1 = host.create_workload("workload1")
            rc = host.calicoctl("container add %s ipv4" % workload1)
            ip1 = get_ip_from_container_add_output(rc)
            assert ip1 in default_cidr

            workload2 = host.create_workload("workload2")
            rc = host.calicoctl("container add %s ipv4" % workload2)
            ip2 = get_ip_from_container_add_output(rc)
            assert ip2 in default_cidr

            # Delete the pool and try to create another workload and assign
            # an IP.  This will fail due to no more valid addresses.
            host.calicoctl("pool remove %s" % default_cidr)
            workload3 = host.create_workload("workload3")
            with self.assertRaises(CalledProcessError):
                host.calicoctl("container add %s ipv4" % workload3)

            # Add the pool back again, and make sure we get an IP assigned
            # in the pool range.
            host.calicoctl("pool add %s" % default_cidr)
            rc = host.calicoctl("container add %s ipv4" % workload3)
            ip3 = get_ip_from_container_add_output(rc)
            assert ip3 in default_cidr

            # Delete the pool and add a new pool.  Assign another IP to
            # workload 3 and make sure it comes from the new pool.
            host.calicoctl("pool remove %s" % default_cidr)
            host.calicoctl("pool add %s" % new_cidr)
            rc = host.calicoctl("container %s ip add ipv4" % workload3)
            ip4 = get_ip_from_container_add_output(rc)
            assert ip4 in new_cidr

            # Delete the new pool and re-add it.  Assign another IP to
            # workload 3 and make sure it comes from the new pool.  This
            # checks that we can still assign from a non-affine block since
            # the pool is the same size as an affine block (so we will be
            # assigning from the same block that we used to have affinity
            # for).
            host.calicoctl("pool remove %s" % new_cidr)
            host.calicoctl("pool add %s" % new_cidr)
            rc = host.calicoctl("container %s ip add ipv4" % workload3)
            ip5 = get_ip_from_container_add_output(rc)
            assert ip5 in new_cidr

            # Finally remove all IPs and then remove the new pool.  Check
            # that we have allocation blocks before and none after
            # (by sneakily querying etcd).
            data = self.curl_etcd("calico/ipam/v2/assignment/ipv4/block")
            assert data["node"].get("nodes")

            host.calicoctl("container %s ip remove %s" % (workload1, ip1))
            host.calicoctl("container %s ip remove %s" % (workload2, ip2))
            host.calicoctl("container %s ip remove %s" % (workload3, ip3))
            host.calicoctl("container %s ip remove %s" % (workload3, ip4))
            host.calicoctl("container %s ip remove %s" % (workload3, ip5))
            host.calicoctl("pool remove %s" % new_cidr)

            data = self.curl_etcd("calico/ipam/v2/assignment/ipv4/block")
            assert not data["node"].get("nodes")
