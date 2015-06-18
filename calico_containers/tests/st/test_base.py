# Copyright 2015 Metaswitch Networks
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
from sh import docker, ErrorReturnCode_1
from functools import partial
from unittest import TestCase
import os

from utils import get_ip, delete_container, retry_until_success

TEARDOWN_ENV = "CALICO_TEARDOWN"

def do_teardown():
    """Returns whether we should build the node and calicoctl binaries."""
    try:
        teardown = os.environ[TEARDOWN_ENV]
        return teardown.lower() not in ["no", "n", "f", "false"]
    except KeyError:
        return True


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        """
        Clean up host containers before every test.
        """
        containers = docker.ps("-qa").split()
        for container in containers:
            delete_container(container)

        self.ip = get_ip()
        self.start_etcd()

    def tearDown(self):
        """
        Clean up host containers after every test.
        """
        if do_teardown():
            containers = docker.ps("-qa").split()
            for container in containers:
                delete_container(container)

    def start_etcd(self):
        """
        Starts the single-node etcd cluster.

        The etcd process runs within its own container, outside the host
        containers. It uses port mapping and the base machine's IP to communicate.
        """

        docker.run(
            "--detach",
            "--publish", "2379:2379",
            "--publish", "2380:2380",
            "--name", "etcd", "quay.io/coreos/etcd:v2.0.11",
            name="calico",
            advertise_client_urls="http://%s:2379" % self.ip,
            listen_client_urls="http://0.0.0.0:2379",
            initial_advertise_peer_urls="http://%s:2380" % self.ip,
            listen_peer_urls="http://0.0.0.0:2380",
            initial_cluster_token="etcd-cluster-2",
            initial_cluster="calico=http://%s:2380" % self.ip,
            initial_cluster_state="new",
        )

    def assert_connectivity(self, pass_list, fail_list=[]):
        """
        Assert partial connectivity graphs between workloads.

        :param pass_list: Every workload in this list should be able to ping
        every other workload in this list.
        :param fail_list: Every workload in pass_list should *not* be able to
        ping each workload in this list. Interconnectivity is not checked
        *within* the fail_list.
        """
        for source in pass_list:
            for dest in pass_list:
                source.assert_can_ping(dest.ip)
            for dest in fail_list:
                with self.assertRaises(ErrorReturnCode_1):
                    source.assert_can_ping(dest.ip)
