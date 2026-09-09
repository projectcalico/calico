# -*- coding: utf-8 -*-
# Copyright (c) 2026 Tigera, Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""
test_fv_dhcp_agent
~~~~~~~~~~~~~~~~~~

Tests for the Calico DHCP agent with a real etcd server, focussing on subnet
CIDR re-use.

When a Neutron network is deleted and another network is then created with the
same subnet CIDR, the new network's dnsmasq cannot bind its listening socket
until the old network's dnsmasq has been stopped, because both want to listen
on the same gateway IP.  The real dnsmasq driver reacts to that bind failure
by retrying the spawn, inside the driver call, for several minutes; and the
agent's DnsmasqUpdater processes all driver calls in series on a single
thread.  So if the start of the new dnsmasq is attempted before the stop of
the old one, the stop is queued behind a driver call that can only fail, and
DHCP service is lost for all networks until the driver call times out.  These
tests reproduce that scenario with a fake driver that models just the
address-conflict and blocking-retry behaviours.
"""

from __future__ import print_function

# These are functional-verification tests: they need a real etcd binary on
# disk and use eventlet's cooperative I/O.  As for test_fv_etcdutils.py, the
# whole file is opt-in via the CALICO_RUN_FV_TESTS=1 environment variable, so
# that importing it under the standard tox / subunit unit-test discovery does
# not monkey-patch that test process.
import os

_FV_ENABLED = os.environ.get("CALICO_RUN_FV_TESTS") == "1"

import eventlet

if _FV_ENABLED:
    eventlet.monkey_patch()

import json  # noqa: I100
import logging
import shutil
import socket
import subprocess
import time
import unittest

import mock

from oslo_config import cfg

from networking_calico import datamodel_v2
from networking_calico import datamodel_v3
from networking_calico import etcdv3
from networking_calico.common import config as calico_config

_log = logging.getLogger(__name__)

# The CIDR that both test networks share, and its gateway IP, on which each
# network's dnsmasq must listen.
CIDR = "10.65.0.0/24"
GATEWAY_IP = "10.65.0.1"


class FakeDnsmasqFleet(object):
    """Test double for the DHCP agent's call_driver method.

    This models the two behaviours of the real dnsmasq driver stack that
    matter for CIDR re-use:

    1. A network's dnsmasq process listens on that network's gateway IP(s),
       in the root namespace, so only one network with a given gateway IP can
       have a running dnsmasq at any time.

    2. When the listening address is already in use, an 'enable' or 'restart'
       driver call does not fail promptly: the driver and process-monitor
       machinery keeps retrying the spawn, blocking the calling thread, for
       RETRY_SECS.  (Observed as ~5 minutes for the real driver.)
    """

    RETRY_SECS = 60

    def __init__(self):
        # Map from network ID to the set of gateway IPs that that network's
        # running dnsmasq instance is listening on.
        self.gateways_by_network = {}

        # Networks for which an enable/restart call is currently blocked,
        # retrying, because the address is in use.
        self.blocked_networks = set()

        # Record of (action, network_id) driver calls, for debuggability.
        self.calls = []

    def running(self, network_id):
        return network_id in self.gateways_by_network

    def call_driver(self, action, network, **kwargs):
        _log.info("call_driver: %s %s", action, network.id)
        self.calls.append((action, network.id))
        if action == "disable":
            self.gateways_by_network.pop(network.id, None)
        elif action in ("enable", "restart"):
            # A restart stops any existing instance for this network first.
            self.gateways_by_network.pop(network.id, None)
            wanted = set(subnet.gateway_ip for subnet in network.subnets)
            deadline = time.monotonic() + self.RETRY_SECS

            # Retry, blocking this thread, while another network's dnsmasq
            # holds any of the addresses that we want to listen on.
            while any(
                wanted & held
                for other_id, held in self.gateways_by_network.items()
                if other_id != network.id
            ):
                if time.monotonic() > deadline:
                    _log.warning("Giving up starting dnsmasq for %s", network.id)
                    self.blocked_networks.discard(network.id)
                    return False
                self.blocked_networks.add(network.id)
                eventlet.sleep(0.1)
            self.blocked_networks.discard(network.id)
            self.gateways_by_network[network.id] = wanted
        return True


@unittest.skipUnless(_FV_ENABLED, "set CALICO_RUN_FV_TESTS=1 to run FV tests")
class TestFVDhcpAgent(unittest.TestCase):
    def setUp(self):
        super(TestFVDhcpAgent, self).setUp()
        self.etcd_server_running = False
        self.greenlets = []
        self.agent = None

        # Track every green thread spawned during the test - including those
        # spawned internally by CalicoEtcdWatcher.start() - so that tearDown
        # can kill them all.
        self._real_spawn = eventlet.spawn

        def tracking_spawn(*args, **kwargs):
            greenlet = self._real_spawn(*args, **kwargs)
            self.greenlets.append(greenlet)
            return greenlet

        self._spawn_patch = mock.patch("eventlet.spawn", new=tracking_spawn)
        self._spawn_patch.start()

        # The agent code path doesn't need to create real directories here.
        self._makedirs_patch = mock.patch("os.makedirs")
        self._makedirs_patch.start()

    def tearDown(self):
        if self.agent:
            self.agent.etcd.stop()
            self.agent.etcd.v1_subnet_watcher.stop()
            self.agent.etcd.subnet_watcher.stop()
        for greenlet in reversed(self.greenlets):
            try:
                greenlet.kill()
            except Exception:
                pass
        self._makedirs_patch.stop()
        self._spawn_patch.stop()
        self.stop_etcd_server()
        etcdv3._client = None
        super(TestFVDhcpAgent, self).tearDown()

    # Real etcd server management, as in test_fv_etcdutils.py.
    def start_etcd_server(self):
        shutil.rmtree(".default.etcd", ignore_errors=True)
        shutil.rmtree("default.etcd", ignore_errors=True)
        self.etcd = subprocess.Popen(
            [
                "/usr/local/bin/etcd",
                "--advertise-client-urls",
                "http://127.0.0.1:2379",
                "--listen-client-urls",
                "http://0.0.0.0:2379",
                "--log-level",
                "error",
            ]
        )
        self.etcd_server_running = True

    def wait_etcd_ready(self):
        self.assertTrue(self.etcd_server_running)
        ready = False
        for ii in range(10):
            try:
                _log.warning("Try connecting to etcd server...")
                etcdv3.get_status()
                ready = True
                break
            except Exception:
                _log.exception("etcd server not ready yet")
                eventlet.sleep(2)
        self.assertTrue(ready)

    def stop_etcd_server(self):
        if self.etcd_server_running:
            self.etcd.kill()
            self.etcd.wait()
        self.etcd_server_running = False

    def start_agent(self):
        """Create a Calico DHCP agent, with a fake driver, and start it."""

        # Import here so that neutron code is only pulled in when the FV
        # tests are actually enabled and running.
        from neutron.agent.dhcp_agent import register_options
        from neutron_lib import rpc as n_rpc
        from networking_calico.agent.dhcp_agent import CalicoDhcpAgent

        register_options(cfg.CONF)
        calico_config.register_options(cfg.CONF)

        # The base neutron DhcpAgent class sets up an RPC client, which
        # needs a messaging transport to exist, even though the Calico agent
        # then immediately replaces that client with FakePlugin.
        if not n_rpc.TRANSPORT:
            from oslo_messaging import conffixture as messaging_conffixture

            messaging_conf = messaging_conffixture.ConfFixture(cfg.CONF)
            messaging_conf.setUp()
            messaging_conf.transport_url = "fake://"
            self.addCleanup(messaging_conf.cleanUp)
            n_rpc.init(cfg.CONF)
            self.addCleanup(n_rpc.cleanup)
        self.hostname = socket.gethostname()
        cfg.CONF.host = self.hostname
        self.region_string = calico_config.get_region_string()
        self.namespace = datamodel_v3.get_namespace(self.region_string)

        self.agent = CalicoDhcpAgent()

        # Divert all driver calls to the fake dnsmasq fleet.
        self.fake_fleet = FakeDnsmasqFleet()
        self.agent.call_driver = self.fake_fleet.call_driver

        # Fake the MTU watcher; its real implementation runs 'ip monitor
        # link', and an endpoint's dnsmasq update is deferred until the MTU
        # for its TAP interface is known.
        self.agent.etcd.mtu_watcher = mock.Mock()
        self.agent.etcd.mtu_watcher.get_mtu.return_value = 1500

        eventlet.spawn(self.agent.etcd.start)

    def wait_for(self, description, predicate, timeout_secs=10):
        deadline = time.monotonic() + timeout_secs
        while time.monotonic() < deadline:
            if predicate():
                return
            eventlet.sleep(0.1)
        self.fail(
            "Timed out (%ss) waiting for %s; driver calls were %r"
            % (timeout_secs, description, self.fake_fleet.calls)
        )

    # Writing and deleting the etcd data that the mechanism driver would
    # write for a network's subnet and for a VM port's WorkloadEndpoint.
    def write_subnet(self, subnet_id, network_id):
        etcdv3.put(
            datamodel_v2.key_for_subnet(subnet_id, self.region_string),
            json.dumps(
                {
                    "network_id": network_id,
                    "cidr": CIDR,
                    "gateway_ip": GATEWAY_IP,
                    "host_routes": [],
                }
            ),
        )
        self.wait_for(
            "subnet %s to be seen by the agent" % subnet_id,
            lambda: subnet_id in self.agent.etcd.subnet_watcher.subnets_by_id,
        )

    def delete_subnet(self, subnet_id):
        etcdv3.delete(datamodel_v2.key_for_subnet(subnet_id, self.region_string))

    def endpoint_name(self, workload_id, endpoint_id):
        parts = [self.hostname, "openstack", workload_id, endpoint_id]
        return "-".join(p.replace("-", "--") for p in parts)

    def write_endpoint(self, workload_id, endpoint_id, network_id, if_name, ip):
        name = self.endpoint_name(workload_id, endpoint_id)
        self.assertTrue(
            datamodel_v3.put(
                "WorkloadEndpoint",
                self.namespace,
                name,
                {
                    "orchestrator": "openstack",
                    "workload": workload_id,
                    "node": self.hostname,
                    "endpoint": endpoint_id,
                    "interfaceName": if_name,
                    "mac": "fa:16:3e:00:00:01",
                    "ipNetworks": ["%s/32" % ip],
                    "allowedIps": [],
                },
                annotations={datamodel_v3.ANN_KEY_NETWORK_ID: network_id},
            )
        )
        return name

    def delete_endpoint(self, name):
        self.assertTrue(datamodel_v3.delete("WorkloadEndpoint", self.namespace, name))

    def test_cidr_reuse(self):
        # Start a real local etcd server, and an agent against it.
        self.start_etcd_server()
        calico_config.register_options(cfg.CONF)
        self.wait_etcd_ready()
        self.start_agent()

        # Create network A: one subnet and one VM port.  Its dnsmasq should
        # start, listening on the gateway IP.
        self.write_subnet("subnet-a", "net-a")
        endpoint_a = self.write_endpoint(
            "vm-a", "port-a", "net-a", "tapa", "10.65.0.10"
        )
        self.wait_for(
            "dnsmasq for net-a to start",
            lambda: self.fake_fleet.running("net-a"),
        )

        # Create network B, re-using the same CIDR, before the agent has any
        # reason to stop network A's dnsmasq.  The driver call to start
        # network B's dnsmasq cannot succeed yet - the gateway IP is still
        # held - and blocks, retrying.
        self.write_subnet("subnet-b", "net-b")
        self.write_endpoint("vm-b", "port-b", "net-b", "tapb", "10.65.0.20")
        self.wait_for(
            "dnsmasq start for net-b to be attempted and blocked",
            lambda: "net-b" in self.fake_fleet.blocked_networks,
        )

        # Now delete network A's port and subnet, as when the VM and then the
        # network are deleted in Neutron.  The agent should promptly stop
        # network A's dnsmasq, whereupon network B's dnsmasq can come up.
        self.delete_endpoint(endpoint_a)
        self.delete_subnet("subnet-a")
        self.wait_for(
            "dnsmasq for net-a to be stopped",
            lambda: not self.fake_fleet.running("net-a"),
            timeout_secs=15,
        )
        self.wait_for(
            "dnsmasq for net-b to start",
            lambda: self.fake_fleet.running("net-b"),
            timeout_secs=15,
        )
