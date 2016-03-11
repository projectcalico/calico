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
import json
import subprocess
from unittest import TestCase

from tests.st.utils.utils import (get_ip, ETCD_SCHEME, ETCD_CA, ETCD_CERT,
                                  ETCD_KEY, debug_failures, ETCD_HOSTNAME_SSL)
import logging

HOST_IPV6 = get_ip(v6=True)
HOST_IPV4 = get_ip()

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

# Disable spammy logging from the sh module
sh_logger = logging.getLogger("sh")
sh_logger.setLevel(level=logging.CRITICAL)


class TestBase(TestCase):
    """
    Base class for test-wide methods.
    """
    def setUp(self):
        """
        Clean up before every test.
        """
        self.ip = HOST_IPV4

        # Delete /calico if it exists. This ensures each test has an empty data
        # store at start of day.
        self.curl_etcd("calico", options=["-XDELETE"])

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

    @debug_failures
    def assert_connectivity(self, pass_list, fail_list=None):
        """
        Assert partial connectivity graphs between workloads.

        :param pass_list: Every workload in this list should be able to ping
        every other workload in this list.
        :param fail_list: Every workload in pass_list should *not* be able to
        ping each workload in this list. Interconnectivity is not checked
        *within* the fail_list.
        """
        if fail_list is None:
            fail_list = []
        for source in pass_list:
            for dest in pass_list:
                source.assert_can_ping(dest.ip)
            for dest in fail_list:
                source.assert_cant_ping(dest.ip)

    @debug_failures
    def assert_ip_connectivity(self, workload_list, ip_pass_list,
                               ip_fail_list=None):
        """
        Assert partial connectivity graphs between workloads and given ips.

        This function is used for checking connectivity for ips that are
        explicitly assigned to containers when added to calico networking.

        :param workload_list: List of workloads used to check connectivity.
        :param ip_pass_list: Every workload in workload_list should be able to
        ping every ip in this list.
        :param ip_fail_list: Every workload in workload_list should *not* be
        able to ping any ip in this list. Interconnectivity is not checked
        *within* the fail_list.
        """
        if ip_fail_list is None:
            ip_fail_list = []
        for workload in workload_list:
            for ip in ip_pass_list:
                workload.assert_can_ping(ip)
            for ip in ip_fail_list:
                workload.assert_cant_ping(ip)

    def curl_etcd(self, path, options=[], recursive=True):
        """
        Perform a curl to etcd, returning JSON decoded response.
        :param path:  The key path to query
        :param options:  Additional options to include in the curl
        :param recursive:  Whether we want recursive query or not
        :return:  The JSON decoded response.
        """
        if ETCD_SCHEME == "https":
            # Etcd is running with SSL/TLS, require key/certificates
            rc = subprocess.check_output(
                "curl --cacert %s --cert %s --key %s "
                "-sL https://%s:2379/v2/keys/%s?recursive=%s %s"
                % (ETCD_CA, ETCD_CERT, ETCD_KEY, ETCD_HOSTNAME_SSL,
                   path, str(recursive).lower(), " ".join(options)),
                shell=True)
        else:
            rc = subprocess.check_output(
                "curl -sL http://%s:2379/v2/keys/%s?recursive=%s %s"
                % (self.ip, path, str(recursive).lower(), " ".join(options)),
                shell=True)

        return json.loads(rc.strip())