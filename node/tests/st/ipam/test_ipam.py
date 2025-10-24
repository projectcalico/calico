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
import logging
import random

import netaddr
import time
import yaml
from nose_parameterized import parameterized

from tests.st.test_base import TestBase
from tests.st.utils.docker_host import DockerHost, CLUSTER_STORE_DOCKER_OPTIONS

POST_DOCKER_COMMANDS = ["docker load -q -i /code/calico-node.tar",
                        "docker load -q -i /code/busybox.tar",
                        "docker load -q -i /code/workload.tar"]

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)


class MultiHostIpam(TestBase):
    @classmethod
    def setUpClass(cls):
        super(MultiHostIpam, cls).setUpClass()
        cls.hosts = []
        cls.hosts.append(DockerHost("host1",
                                    additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                                    post_docker_commands=POST_DOCKER_COMMANDS,
                                    start_calico=False))
        cls.hosts.append(DockerHost("host2",
                                    additional_docker_options=CLUSTER_STORE_DOCKER_OPTIONS,
                                    post_docker_commands=POST_DOCKER_COMMANDS,
                                    start_calico=False))
        cls.hosts[0].start_calico_node()
        cls.hosts[1].start_calico_node()
        cls.network = cls.hosts[0].create_network("testnet1")

    @classmethod
    def tearDownClass(cls):
        # Tidy up
        cls.network.delete()
        for host in cls.hosts:
            host.cleanup()
            del host

    def setUp(self):
        # Save off original pool if any, then wipe pools so we have a known ground state
        response = self.hosts[0].calicoctl("get IPpool -o yaml")
        self.orig_pools = yaml.safe_load(response)['items']
        if len(self.orig_pools) > 0:
            self.hosts[0].writefile("orig_pools.yaml", response)
            self.hosts[0].calicoctl("delete -f orig_pools.yaml")

    def tearDown(self):
        # Replace original pool, if any
        response = self.hosts[0].calicoctl("get IPpool -o yaml")
        self.hosts[0].writefile("testpools.yaml", response)
        self.hosts[0].calicoctl("delete -f testpools.yaml")
        if len(self.orig_pools) > 0:
            self.hosts[0].calicoctl("apply -f orig_pools.yaml")
        # Remove all workloads
        for host in self.hosts:
            host.remove_workloads()

    def test_pools_add(self):
        """
        (Add a pool), create containers, check IPs assigned from pool.
        Then Delete that pool.
        Add a new pool, create containers, check IPs assigned from NEW pool
        """
        response = self.hosts[0].calicoctl("get IPpool -o yaml")
        pools = yaml.safe_load(response)
        if len(pools['items']) > 0:
            self.hosts[0].writefile("pools.yaml", response)
            self.hosts[0].calicoctl("delete -f pools.yaml")

        old_pool_workloads = []
        ipv4_subnet = netaddr.IPNetwork("192.168.11.0/24")
        new_pool = {'apiVersion': 'projectcalico.org/v3',
                    'kind': 'IPPool',
                    'metadata': {'name': 'ippool-name-1'},
                    'spec': {'cidr': str(ipv4_subnet.ipv4())},
                    }
        self.hosts[0].writejson("newpool.json", new_pool)
        self.hosts[0].calicoctl("create -f newpool.json")

        for host in self.hosts:
            workload = host.create_workload("wlda-%s" % host.name,
                                            image="workload",
                                            network=self.network)
            assert netaddr.IPAddress(workload.ip) in ipv4_subnet
            old_pool_workloads.append((workload, host))

        blackhole_cidr = netaddr.IPNetwork(
            self.hosts[0].execute("ip r | grep blackhole").split()[1])
        assert blackhole_cidr in ipv4_subnet
        # Check there's only one /32 present and that its within the pool
        output = self.hosts[0].execute("ip r | grep cali").split('\n')
        assert len(output) == 1, "Output should only be 1 line.  Got: %s" % output
        wl_ip = netaddr.IPNetwork(output[0].split()[0])
        assert wl_ip in ipv4_subnet

        self.hosts[0].remove_workloads()

        self.hosts[0].calicoctl("delete -f newpool.json")
        self.hosts[0].calicoctl("get IPpool -o yaml")

        ipv4_subnet = netaddr.IPNetwork("10.0.1.0/24")
        new_pool = {'apiVersion': 'projectcalico.org/v3',
                    'kind': 'IPPool',
                    'metadata': {'name': 'ippool-name-2'},
                    'spec': {'cidr': str(ipv4_subnet.ipv4())},
                    }
        self.hosts[0].writejson("pools.json", new_pool)
        self.hosts[0].calicoctl("create -f pools.json")

        for host in self.hosts:
            workload = host.create_workload("wlda2-%s" % host.name,
                                            image="workload",
                                            network=self.network)
            assert netaddr.IPAddress(workload.ip) in ipv4_subnet, \
                "Workload IP in wrong pool. IP: %s, Pool: %s" % (workload.ip, ipv4_subnet.ipv4())

        blackhole_cidr = netaddr.IPNetwork(
            self.hosts[0].execute("ip r | grep blackhole").split()[1])
        assert blackhole_cidr in ipv4_subnet
        # Check there's only one /32 present and that its within the pool
        output = self.hosts[0].execute("ip r | grep cali").split('\n')
        assert len(output) == 1, "Output should only be 1 line.  Got: %s" % output
        wl_ip = netaddr.IPNetwork(output[0].split()[0])
        assert wl_ip in ipv4_subnet

    def test_ipam_show(self):
        """
        Create some workloads, then ask calicoctl to tell you about the IPs in the pool.
        Check that the correct IPs are shown as in use.
        """
        num_workloads = 2
        workload_ips = []

        ipv4_subnet = netaddr.IPNetwork("192.168.45.0/25")
        new_pool = {'apiVersion': 'projectcalico.org/v3',
                    'kind': 'IPPool',
                    'metadata': {'name': 'ippool-name-3'},
                    'spec': {'cidr': str(ipv4_subnet.ipv4())},
                    }
        self.hosts[0].writejson("newpool.json", new_pool)
        self.hosts[0].calicoctl("create -f newpool.json")

        for i in range(num_workloads):
            host = random.choice(self.hosts)
            workload = host.create_workload("wlds-%s" % i,
                                            image="workload",
                                            network=self.network)
            workload_ips.append(workload.ip)

        print workload_ips

        for ip in ipv4_subnet:
            response = self.hosts[0].calicoctl("ipam show --ip=%s" % ip)
            if "No attributes defined for" in response:
                # This means the IP is assigned
                assert str(ip) in workload_ips, "ipam show says IP %s " \
                                                "is assigned when it is not" % ip
            if "not currently assigned in block" in response:
                # This means the IP is not assigned
                assert str(ip) not in workload_ips, \
                    "ipam show says IP %s is not assigned when it is!" % ip

    @staticmethod
    def delete_workload(host, workload):
        host.calicoctl("ipam release --ip=%s" % workload.ip)
        host.execute("docker rm -f %s" % workload.name)
        host.workloads.remove(workload)

MultiHostIpam.batchnumber = 2  # Adds a batch number for parallel testing
