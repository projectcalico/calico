# Copyright (c) 2025-2026 Tigera, Inc. All rights reserved.
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

import copy
import logging
import os

from calicotest.common import datamodel_v3
from calicotest.common.testutils import retry_until_success, run
from calicotest.openstack.config import IPERF_PATH, LAYOUT
from calicotest.openstack.topology import TopologyBasic, TopologyTwoUbuntuVms
from calicotest.openstack.udp_stream import UdpStream

_log = logging.getLogger(__name__)


class TestQoS(TopologyBasic):
    """
    Check setting QoS parameters on VM ports.
    """

    def setUp(self):
        super(TestQoS, self).setUp()

        # Get the port of the first VM.
        vm_ip = str(self.vms[0].get_ip_addr())
        port = self.get_port(vm_ip)
        self.port_id = port["id"]

        self.region_arg = self._datamodel_region_arg()

        # Find the name of the corresponding WorkloadEndpoint in etcd.
        _log.info("Searching for endpoint in etcd")
        endpoints = datamodel_v3.get_all("WorkloadEndpoint", region=self.region_arg)
        if not endpoints:
            raise RuntimeError("No endpoints found in etcd!")

        escaped_port_id = self.port_id.replace("-", "--")
        self.wep_name = None

        for endpoint in endpoints:
            # Unpack the endpoint tuple.
            name, spec, mod_revision = endpoint
            if escaped_port_id in name:
                self.wep_name = name
                _log.info("Found WEP name %r", self.wep_name)
                break

        if not self.wep_name:
            raise RuntimeError("Couldn't find WEP!")

        # Prepare environment for "openstack ..." calls.  Take the admin password from
        # the layout file, because it varies between deployments.  Build self.env as
        # a copy of the process environment plus these settings, and pass it
        # explicitly to each command: an earlier version of this code relied on
        # copy.deepcopy(os.environ).update(...), which returns None and also
        # modifies the process environment itself.
        admin_password = LAYOUT.control_node.admin_password
        self.env = copy.deepcopy(os.environ)
        self.env.update(
            {
                "ADMIN_PASSWORD": admin_password,
                "OS_TENANT_NAME": "admin",
                "OS_USERNAME": "admin",
                "OS_PASSWORD": admin_password,
                "OS_AUTH_URL": "http://controller:5000/v3",
                "OS_IDENTITY_API_VERSION": "3",
                "OS_IMAGE_API_VERSION": "2",
                "OS_PROJECT_DOMAIN_NAME": "Default",
                "OS_USER_DOMAIN_NAME": "Default",
            }
        )

    def tearDown(self):
        # Remove QoS policy from the VM port.
        run(
            "openstack port unset --qos-policy " + self.port_id,
            env=self.env,
            # Because it might have already been unset.
            allow_fail=True,
        )

        # Delete QoS policy.
        run(
            "openstack network qos policy delete bw-limiter",
            env=self.env,
            # Because it might have already been deleted.
            allow_fail=True,
        )

        super(TestQoS, self).tearDown()

    def test_qos(self):
        # Create QoS policy.
        run("openstack network qos policy create bw-limiter", env=self.env)

        # Create rule to limit egress bandwidth.
        run(
            "openstack network qos rule create --type bandwidth-limit"
            + " --max-kbps 3000 --max-burst-kbits 2400 --egress bw-limiter",
            env=self.env,
        )
        self.trigger_port_qos_update()
        self.check_wep_qos(
            {
                "egressBandwidth": 3000000,
                "egressBurst": 4294967296,
                "egressPeakrate": 2400000,
            }
        )

        # Add an ingress bandwidth rule.
        run(
            "openstack network qos rule create --type bandwidth-limit"
            + " --max-kbps 123 --max-burst-kbits 456 --ingress bw-limiter",
            env=self.env,
        )
        self.trigger_port_qos_update()
        self.check_wep_qos(
            {
                "ingressBandwidth": 123000,
                "ingressBurst": 4294967296,
                "ingressPeakrate": 456000,
                "egressBandwidth": 3000000,
                "egressBurst": 4294967296,
                "egressPeakrate": 2400000,
            }
        )

        # Add an ingress packet rate rule.
        run(
            "openstack network qos rule create --type packet-rate-limit"
            + " --max-kpps 9 --ingress bw-limiter",
            env=self.env,
        )
        self.trigger_port_qos_update()
        self.check_wep_qos(
            {
                "ingressBandwidth": 123000,
                "ingressBurst": 4294967296,
                "ingressPeakrate": 456000,
                "ingressPacketRate": 9000,
                "ingressPacketBurst": 5,
                "egressBandwidth": 3000000,
                "egressBurst": 4294967296,
                "egressPeakrate": 2400000,
            }
        )

        # Add an egress packet rate rule.
        run(
            "openstack network qos rule create --type packet-rate-limit"
            + " --max-kpps 8 --egress bw-limiter",
            env=self.env,
        )
        self.trigger_port_qos_update()
        self.check_wep_qos(
            {
                "ingressBandwidth": 123000,
                "ingressBurst": 4294967296,
                "ingressPeakrate": 456000,
                "ingressPacketRate": 9000,
                "ingressPacketBurst": 5,
                "egressBandwidth": 3000000,
                "egressBurst": 4294967296,
                "egressPeakrate": 2400000,
                "egressPacketRate": 8000,
                "egressPacketBurst": 5,
            }
        )

    def check_wep_qos(self, expected_qos_controls):
        def check():
            wep_spec = datamodel_v3.get(
                "WorkloadEndpoint", self.wep_name, region=self.region_arg
            )
            assert "qosControls" in wep_spec
            self.assertEqual(wep_spec["qosControls"], expected_qos_controls)

        retry_until_success(check)

    def trigger_port_qos_update(self):
        run(
            "openstack port unset --qos-policy " + self.port_id,
            env=self.env,
            # In case it is already unset.
            allow_fail=True,
        )
        run("openstack port set --qos-policy bw-limiter " + self.port_id, env=self.env)


class TestQoSIPerf(TopologyTwoUbuntuVms):
    """
    Check setting QoS parameters on VM ports.
    """

    @classmethod
    def setUpClass(cls):
        super(TestQoSIPerf, cls).setUpClass()
        # Install iperf on the Ubuntu VMs.
        cls.vms[0].install_dpkg_from_test_rig(IPERF_PATH)
        cls.vms[1].install_dpkg_from_test_rig(IPERF_PATH)
        cls.add_group_rule(cls.UBUNTU_GROUPNAME, cls.UBUNTU_GROUPNAME, "udp")

    def setUp(self):
        super(TestQoSIPerf, self).setUp()

        # Get the port of the first VM.
        vm_ip = str(self.vms[0].get_ip_addr())
        port = self.get_port(vm_ip)
        self.port_id = port["id"]

        self.region_arg = self._datamodel_region_arg()

        # Find the name of the corresponding WorkloadEndpoint in etcd.
        _log.info("Searching for endpoint in etcd")
        endpoints = datamodel_v3.get_all("WorkloadEndpoint", region=self.region_arg)
        if not endpoints:
            raise RuntimeError("No endpoints found in etcd!")

        escaped_port_id = self.port_id.replace("-", "--")
        self.wep_name = None

        for endpoint in endpoints:
            # Unpack the endpoint tuple.
            name, spec, mod_revision = endpoint
            if escaped_port_id in name:
                self.wep_name = name
                _log.info("Found WEP name %r", self.wep_name)
                break

        if not self.wep_name:
            raise RuntimeError("Couldn't find WEP!")

        # Prepare environment for "openstack ..." calls.  Take the admin password from
        # the layout file, because it varies between deployments.  Build self.env as
        # a copy of the process environment plus these settings, and pass it
        # explicitly to each command: an earlier version of this code relied on
        # copy.deepcopy(os.environ).update(...), which returns None and also
        # modifies the process environment itself.
        admin_password = LAYOUT.control_node.admin_password
        self.env = copy.deepcopy(os.environ)
        self.env.update(
            {
                "ADMIN_PASSWORD": admin_password,
                "OS_TENANT_NAME": "admin",
                "OS_USERNAME": "admin",
                "OS_PASSWORD": admin_password,
                "OS_AUTH_URL": "http://controller:5000/v3",
                "OS_IDENTITY_API_VERSION": "3",
                "OS_IMAGE_API_VERSION": "2",
                "OS_PROJECT_DOMAIN_NAME": "Default",
                "OS_USER_DOMAIN_NAME": "Default",
            }
        )

    def tearDown(self):
        # Remove QoS policy from the VM port.
        run(
            "openstack port unset --qos-policy " + self.port_id,
            env=self.env,
            # Because it might have already been unset.
            allow_fail=True,
        )

        # Delete QoS policy.
        run(
            "openstack network qos policy delete bw-limiter",
            env=self.env,
            # Because it might have already been deleted.
            allow_fail=True,
        )

        super(TestQoSIPerf, self).tearDown()

    def test_qos_egress(self):
        self.run_qos_test(direction="egress")

    def test_qos_ingress(self):
        self.run_qos_test(direction="ingress")

    def run_qos_test(self, direction="egress"):
        _log.info("Starting QoS perf test, direction=%s", direction)
        self.assertIn(direction, ["ingress", "egress"])

        # The natural bandwidth in our OpenStack ST is about 1 Mbit/s.  We will
        # apply QoS to limit that to a peak of 500 kbps.
        max_kbps = 300
        max_burst = 500

        # Run iperf between the two VMs before configuring any QoS.  Expect to
        # see no packet loss, and that the bandwidth observed by the server is
        # larger than the limit that we will configure below.
        stream = self.run_iperf()
        self.assertTrue(
            stream.completed_successfully(), msg="The UDP stream suffered packet loss"
        )
        self.assertGreater(stream.server_bandwidth_kbps(), max_burst)

        # Create QoS policy.
        run("openstack network qos policy create bw-limiter", env=self.env)

        # Create rule to limit egress bandwidth.
        run(
            "openstack network qos rule create --type bandwidth-limit"
            + " --max-kbps %d --max-burst-kbits %d --%s bw-limiter"
            % (max_kbps, max_burst, direction),
            env=self.env,
        )
        self.trigger_port_qos_update()
        self.check_wep_qos(
            {
                "%sBandwidth" % (direction): max_kbps * 1000,
                "%sBurst" % (direction): 4294967296,
                "%sPeakrate" % (direction): max_burst * 1000,
            }
        )

        # Verify that the tbf qdisc shows up in 'sudo tc qdisc' in the compute node
        node = LAYOUT.compute_nodes[0]
        qdisc = node.execute(
            "sudo tc qdisc | grep 'qdisc tbf .*: dev.*rate %d.*peakrate %d.*'"
            % (max_kbps, max_burst)
        )
        _log.info(
            "compute_node %s: 'tc qdisc | grep ...' output:\n%s" % (node, qdisc.stdout)
        )
        self.assertEqual(qdisc.return_code, 0)

        # Run iperf again.  Expect to see packet loss - i.e. the server
        # receiving a smaller amount of data than the client sent - and the
        # server observing a bandwidth that matches the limit we have
        # configured.
        stream = self.run_iperf(server_timeout=True, direction=direction)
        self.assertLessEqual(stream.server_bandwidth_kbps(), max_burst)

    def check_wep_qos(self, expected_qos_controls):
        def check():
            wep_spec = datamodel_v3.get(
                "WorkloadEndpoint", self.wep_name, region=self.region_arg
            )
            assert "qosControls" in wep_spec
            self.assertEqual(wep_spec["qosControls"], expected_qos_controls)

        retry_until_success(check)

    def run_iperf(self, server_timeout=False, direction="egress"):
        self.assertIn(direction, ["ingress", "egress"])

        src, dst = self.vms[0], self.vms[1]
        if direction == "ingress":
            src, dst = self.vms[1], self.vms[0]

        stream = UdpStream(src, dst, server_timeout=server_timeout)

        stream.start_stream()
        if not stream.wait_for_stream_to_finish():
            self.assertTrue(
                False,
                msg="The UDP stream did not complete; client:\n%s\nserver:\n%s"
                % (stream.client_output(), stream.server_output()),
            )
        return stream

    def trigger_port_qos_update(self):
        run(
            "openstack port unset --qos-policy " + self.port_id,
            env=self.env,
            # In case it is already unset.
            allow_fail=True,
        )
        run("openstack port set --qos-policy bw-limiter " + self.port_id, env=self.env)
