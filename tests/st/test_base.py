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
import hashlib
import json
import logging
import subprocess
import time
import types
from multiprocessing.dummy import Pool as ThreadPool
from pprint import pformat
from unittest import TestCase

import yaml
from deepdiff import DeepDiff

from tests.st.utils.utils import (get_ip, ETCD_SCHEME, ETCD_CA, ETCD_CERT,
                                  ETCD_KEY, debug_failures, ETCD_HOSTNAME_SSL,
                                  wipe_etcd, clear_on_failures)

# The number of test batches used in CI.
NUM_BATCHES = 6

HOST_IPV6 = get_ip(v6=True)
HOST_IPV4 = get_ip()

logging.basicConfig(level=logging.DEBUG, format="%(message)s")
logger = logging.getLogger(__name__)

# Disable spammy logging from the sh module
sh_logger = logging.getLogger("sh")
sh_logger.setLevel(level=logging.CRITICAL)

first_log_time = None


def calculate_batch(cname, mname):
    combined = cname + "." + mname
    m = hashlib.sha224()
    m.update(combined)
    batch = ord(m.digest()[0]) % NUM_BATCHES
    print "Assigned %s to batch %s" % (combined, batch)
    return batch


class AutoBatcher(type):
    """
    AutoBatcher is a metaclass that makes sure every test_ method has a batchnumber.

    Batch numbers are assigned deterministically using a hash of class name and
    method name.
    """

    def __init__(cls, name, bases, dct):
        test_methods_with_no_batch = {}
        has_batch = False
        for k, v in dct.iteritems():
            if k == "batchnumber":
                has_batch = True
            elif k.startswith("test_"):
                if not isinstance(v, types.FunctionType):
                    continue
                if hasattr(v, "batchnumber"):
                    continue
                test_methods_with_no_batch[k] = v
        if not has_batch:
            for k, v in test_methods_with_no_batch.iteritems():
                v.batchnumber = calculate_batch(name, k)
            dct["batchnumber"] = calculate_batch(name, "__class__")
        super(AutoBatcher, cls).__init__(name, bases, dct)


class TestBase(TestCase):
    __metaclass__ = AutoBatcher

    """
    Base class for test-wide methods.
    """
    @classmethod
    def setUpClass(cls):
        wipe_etcd(HOST_IPV4)

    def setUp(self, clear_etcd=True):
        """
        Clean up before every test.
        """
        self.ip = HOST_IPV4

        if clear_etcd:
            wipe_etcd(self.ip)

        # Log a newline to ensure that the first log appears on its own line.
        logger.info("")

        clear_on_failures()

    @staticmethod
    def _conn_checker(args):
        source, dest, test_type, result, retries = args
        if test_type == 'icmp':
            if result:
                return source.check_can_ping(dest, retries)
            else:
                return source.check_cant_ping(dest, retries)
        elif test_type == 'tcp':
            if result:
                return source.check_can_tcp(dest, retries)
            else:
                return source.check_cant_tcp(dest, retries)
        elif test_type == 'udp':
            if result:
                return source.check_can_udp(dest, retries)
            else:
                return source.check_cant_udp(dest, retries)
        else:
            logger.error("Unrecognised connectivity check test_type")

    @debug_failures
    def assert_connectivity(self, pass_list, fail_list=None, retries=0,
                            type_list=None):
        """
        Assert partial connectivity graphs between workloads.

        :param pass_list: Every workload in this list should be able to ping
        every other workload in this list.
        :param fail_list: Every workload in pass_list should *not* be able to
        ping each workload in this list. Interconnectivity is not checked
        *within* the fail_list.
        :param retries: The number of retries.
        :param type_list: list of types to test.  If not specified, defaults to
        icmp only.
        """
        if type_list is None:
            type_list = ['icmp', 'tcp', 'udp']
        if fail_list is None:
            fail_list = []

        # Wait (up to 20 retries) for each of the workloads to be able to ping
        # _itself_.  That will ensure that each workload is properly up and
        # running.
        self.wait_assert_self_connectivity(pass_list + fail_list, type_list)

        # Now check that connectivity _between_ the workloads is as expected.
        conn_check_list = []
        for source in pass_list:
            for dest in pass_list:
                if source is dest:
                    continue
                if 'icmp' in type_list:
                    conn_check_list.append((source, dest.ip, 'icmp', True, retries))
                if 'tcp' in type_list:
                    conn_check_list.append((source, dest.ip, 'tcp', True, retries))
                if 'udp' in type_list:
                    conn_check_list.append((source, dest.ip, 'udp', True, retries))
            for dest in fail_list:
                if 'icmp' in type_list:
                    conn_check_list.append((source, dest.ip, 'icmp', False, retries))
                if 'tcp' in type_list:
                    conn_check_list.append((source, dest.ip, 'tcp', False, retries))
                if 'udp' in type_list:
                    conn_check_list.append((source, dest.ip, 'udp', False, retries))

        results, diagstring = self.probe_connectivity(conn_check_list)
        assert False not in results, ("Connectivity check error!\r\n"
                                      "Results:\r\n %s\r\n" % diagstring)

    def wait_assert_self_connectivity(self, workloads, type_list):
        # First check that each of the workloads that we're looking at can ping
        # _itself_, allowing 20 retries for that.
        self_conn_list = []
        for source in workloads:
            if 'icmp' in type_list:
                self_conn_list.append((source, source.ip, 'icmp', True, 20))
            if 'tcp' in type_list:
                self_conn_list.append((source, source.ip, 'tcp', True, 20))
            if 'udp' in type_list:
                self_conn_list.append((source, source.ip, 'udp', True, 20))

        results, diagstring = self.probe_connectivity(self_conn_list)
        assert False not in results, ("Self-connectivity check error!\r\n"
                                      "Results:\r\n %s\r\n" % diagstring)

    def probe_connectivity(self, conn_check_list):
        # Empirically, 18 threads works well on my machine!
        check_pool = ThreadPool(18)
        results = check_pool.map(self._conn_checker, conn_check_list)
        check_pool.close()
        check_pool.join()
        # _conn_checker should only return None if there is an error in calling it
        assert None not in results, ("_conn_checker error - returned None")
        diagstring = ""
        # Check that all tests passed
        if False in results:
            # We've failed, lets put together some diags.
            header = ["source.ip", "dest.ip", "type", "expected", "actual"]
            diagstring = "{: >18} {: >18} {: >7} {: >6} {: >6}\r\n".format(*header)
            for i in range(len(conn_check_list)):
                source, dest, test_type, exp_result, retries = conn_check_list[i]
                pass_fail = results[i]
                # Convert pass/fail into an actual result
                if not pass_fail:
                    actual_result = not exp_result
                else:
                    actual_result = exp_result
                diag = [source.ip, dest, test_type, exp_result, actual_result]
                diagline = "{: >18} {: >18} {: >7} {: >6} {: >6}\r\n".format(*diag)
                diagstring += diagline

        return results, diagstring

    @debug_failures
    def assert_ip_connectivity(self, workload_list, ip_pass_list,
                               ip_fail_list=None, type_list=None, retries=0):
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
        :param type_list: list of types to test.  If not specified, defaults to
        icmp only.
        """
        if type_list is None:
            type_list = ['icmp']
        if ip_fail_list is None:
            ip_fail_list = []

        # Wait (up to 20 retries) for each of the workloads to be able to ping
        # _itself_.  That will ensure, at least, that each _source_ workload is
        # properly up and running, before we start trying to ping from it to
        # another IP.  (Unfortunately we can't do anything here to ensure that
        # the target IPs are actually available.)
        self.wait_assert_self_connectivity(workload_list, type_list)

        conn_check_list = []
        for workload in workload_list:
            for ip in ip_pass_list:
                if 'icmp' in type_list:
                    conn_check_list.append((workload, ip, 'icmp', True, retries))
                if 'tcp' in type_list:
                    conn_check_list.append((workload, ip, 'tcp', True, retries))
                if 'udp' in type_list:
                    conn_check_list.append((workload, ip, 'udp', True, retries))

            for ip in ip_fail_list:
                if 'icmp' in type_list:
                    conn_check_list.append((workload, ip, 'icmp', False, retries))
                if 'tcp' in type_list:
                    conn_check_list.append((workload, ip, 'tcp', False, retries))
                if 'udp' in type_list:
                    conn_check_list.append((workload, ip, 'udp', False, retries))

        results, diagstring = self.probe_connectivity(conn_check_list)
        assert False not in results, ("Connectivity check error!\r\n"
                                      "Results:\r\n %s\r\n" % diagstring)

    def check_data_in_datastore(self, host, data, resource, yaml_format=True):
        if yaml_format:
            out = host.calicoctl(
                "get %s --output=yaml" % resource)
            output = yaml.safe_load(out)
        else:
            out = host.calicoctl(
                "get %s --output=json" % resource)
            output = json.loads(out)
        self.assert_same(data, output)

    @staticmethod
    def assert_same(thing1, thing2):
        """
        Compares two things.  Debug logs the differences between them before
        asserting that they are the same.
        """
        assert cmp(thing1, thing2) == 0, \
            "Items are not the same.  Difference is:\n %s" % \
            pformat(DeepDiff(thing1, thing2), indent=2)

    @staticmethod
    def writejson(filename, data):
        """
        Converts a python dict to json and outputs to a file.
        :param filename: filename to write
        :param data: dictionary to write out as json
        """
        with open(filename, 'w') as f:
            text = json.dumps(data,
                              sort_keys=True,
                              indent=2,
                              separators=(',', ': '))
            logger.debug("Writing %s: \n%s" % (filename, text))
            f.write(text)

    @debug_failures
    def assert_false(self, b):
        """
        Assert false, wrapped to allow debugging of failures.
        """
        assert not b

    @debug_failures
    def assert_true(self, b):
        """
        Assert true, wrapped to allow debugging of failures.
        """
        assert b

    @staticmethod
    def log_banner(msg, *args, **kwargs):
        global first_log_time
        time_now = time.time()
        if first_log_time is None:
            first_log_time = time_now
        time_now -= first_log_time
        elapsed_hms = "%02d:%02d:%02d " % (time_now / 3600,
                                           (time_now % 3600) / 60,
                                           time_now % 60)

        level = kwargs.pop("level", logging.INFO)
        msg = elapsed_hms + str(msg) % args
        banner = "+" + ("-" * (len(msg) + 2)) + "+"
        logger.log(level, "\n" +
                   banner + "\n"
                            "| " + msg + " |\n" +
                   banner)

# Add a default batch number to all tests (used for running tests in parallel)
TestBase.batchnumber = 0
