# Copyright (c) 2019 Tigera, Inc. All rights reserved.
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
import logging
import subprocess
from kubernetes import client

from tests.k8st.test_base import TestBase
from tests.k8st.utils.utils import \
    retry_until_success, \
    DiagsCollector, \
    calicoctl, \
    calicoctl_apply_dict, \
    kubectl, \
    node_info, \
    generate_unique_id

_log = logging.getLogger(__name__)


class ConnectionError(Exception):
    pass


class TestSpoof(TestBase):
    def setUp(self):
        TestBase.setUp(self)
        self.ns_name = generate_unique_id(5, prefix="spoof")
        self.create_namespace(self.ns_name)
        # Create two client pods that live for the duration of the
        # test.  We will use 'kubectl exec' to try sending/receiving
        # from these at particular times.
        #
        # We do it this way because it takes a
        # relatively long time (7 seconds?) in this test setup for
        # Calico routing and policy to be set up correctly for a newly
        # created pod.
        nodes, _, _ = node_info()
        kubectl("run "
                "access "
                "-n %s "
                "--image busybox "
                "--overrides='{\"spec\": {\"nodeName\":\"%s\"}}' "
                "--command /bin/sh -- -c \"nc -l -u -p 5000 &> /root/snoop.txt\"" % (self.ns_name, nodes[1]))
        kubectl("run "
                "scapy "
                "-n %s "
                "--image calico/scapy:v2.4.0 "
                "--overrides='{\"spec\": {\"nodeName\":\"%s\"}}' "
                "--command /bin/sleep -- 3600" % (self.ns_name, nodes[2]))

        kubectl("wait --timeout=2m --for=condition=ready" +
                " pod/scapy -n %s" % self.ns_name)
        kubectl("wait --timeout=2m --for=condition=ready" +
                " pod/access -n %s" % self.ns_name)

    def tearDown(self):
        # Delete deployment
        self.delete_and_confirm(self.ns_name, "ns")
        # Change pool to use IPIP
        default_pool = json.loads(calicoctl("get ippool default-ipv4-ippool -o json"))
        default_pool["spec"]["vxlanMode"] = "Never"
        default_pool["spec"]["ipipMode"] = "Always"
        calicoctl_apply_dict(default_pool)
        # restart calico-nodes
        kubectl("delete po -n kube-system -l k8s-app=calico-node")
        kubectl("wait --timeout=2m --for=condition=ready" +
                " pods -l k8s-app=calico-node -n kube-system")

    def test_ipip_spoof(self):
        with DiagsCollector():
            # Change pool to use IPIP if necessary
            default_pool = json.loads(calicoctl("get ippool default-ipv4-ippool -o json"))
            if default_pool["spec"]["vxlanMode"] != "Never" or default_pool["spec"]["ipipMode"] != "Always":
                default_pool["spec"]["vxlanMode"] = "Never"
                default_pool["spec"]["ipipMode"] = "Always"
                calicoctl_apply_dict(default_pool)
                # restart calico-nodes
                kubectl("delete po -n kube-system -l k8s-app=calico-node")
                kubectl("wait --timeout=2m --for=condition=ready" +
                        " pods -l k8s-app=calico-node -n kube-system")

            # get busybox pod IP
            remote_pod_ip = retry_until_success(self.get_pod_ip, function_args=["access", self.ns_name])
            print(remote_pod_ip)

            # clear conntrack table on all hosts
            self.clear_conntrack()
            # test connectivity works pod-pod
            retry_until_success(self.send_and_check, function_args=["ipip-normal", remote_pod_ip])

            # clear conntrack table on all hosts
            self.clear_conntrack()

            def send_and_check_ipip_spoof():
                self.send_spoofed_ipip_packet(self.ns_name, "scapy", "10.192.0.3", remote_pod_ip, "ipip-spoofed")
                kubectl("exec -t -n %s access -- grep ipip-spoofed /root/snoop.txt" % self.ns_name)

            def assert_cannot_spoof_ipip():
                failed = True
                try:
                    send_and_check_ipip_spoof()
                except subprocess.CalledProcessError:
                    failed = False
                if failed:
                    print("ERROR - succeeded in sending spoofed IPIP packet")
                    raise ConnectionError

            # test connectivity does NOT work when spoofing
            retry_until_success(assert_cannot_spoof_ipip)

    def test_vxlan_spoof(self):
        with DiagsCollector():
            # Change pool to use VXLAN if necessary
            default_pool = json.loads(calicoctl("get ippool default-ipv4-ippool -o json"))
            if default_pool["spec"]["vxlanMode"] != "Always" or default_pool["spec"]["ipipMode"] != "Never":
                default_pool["spec"]["vxlanMode"] = "Always"
                default_pool["spec"]["ipipMode"] = "Never"
                calicoctl_apply_dict(default_pool)
                # restart calico-nodes
                kubectl("delete po -n kube-system -l k8s-app=calico-node")
                kubectl("wait --timeout=2m --for=condition=ready" +
                        " pods -l k8s-app=calico-node -n kube-system")
            # get busybox pod IP
            remote_pod_ip = retry_until_success(self.get_pod_ip, function_args=["access", self.ns_name])
            print(remote_pod_ip)

            # clear conntrack table on all hosts
            self.clear_conntrack()
            # test connectivity works pod-pod
            retry_until_success(self.send_and_check, function_args=["vxlan-normal", remote_pod_ip])

            # clear conntrack table on all hosts
            self.clear_conntrack()

            def send_and_check_vxlan_spoof():
                self.send_spoofed_vxlan_packet(self.ns_name, "scapy", "10.192.0.3", remote_pod_ip, "vxlan-spoofed")
                kubectl("exec -t -n %s access -- grep vxlan-spoofed /root/snoop.txt" % self.ns_name)

            def assert_cannot_spoof_vxlan():
                failed = True
                try:
                    send_and_check_vxlan_spoof()
                except subprocess.CalledProcessError:
                    failed = False
                if failed:
                    print("ERROR - succeeded in sending spoofed VXLAN packet")
                    raise ConnectionError

            # test connectivity does NOT work when spoofing
            retry_until_success(assert_cannot_spoof_vxlan)

    def send_and_check(self, payload, remote_pod_ip):
        self.send_packet(self.ns_name, "scapy", remote_pod_ip, payload)
        kubectl("exec -t -n %s access -- grep %s /root/snoop.txt" % (self.ns_name, payload))

    @staticmethod
    def clear_conntrack():
        node_dict = json.loads(kubectl("get po "
                                       "-n kube-system "
                                       "-l k8s-app=calico-node "
                                       "-o json"))
        # Flush conntrack in every calico-node pod
        for entry in node_dict["items"]:
            node = entry["metadata"]["name"]
            kubectl("exec -n kube-system %s -- conntrack -F" % node)

    @staticmethod
    def send_packet(ns_name, name, remote_pod_ip, message):
        try:
            kubectl("exec " + name + " -ti -n %s -- "
                                     "scapy << EOF\n"
                                     "send("
                                     "IP(dst='%s')/"
                                     "UDP(dport=5000, sport=5000)/"
                                     "Raw(load='%s'))\n" % (ns_name, remote_pod_ip, message))
        except subprocess.CalledProcessError:
            _log.exception("Failed to send from scapy")
            return False
        _log.debug("scapy sent direct packet")
        return True

    @staticmethod
    def send_spoofed_ipip_packet(ns_name, name, remote_node_ip, remote_pod_ip, message):
        try:
            kubectl("exec " + name + " -ti -n %s -- "
                                     "scapy << EOF\n"
                                     "send("
                                     "IP(dst='%s')/"
                                     "IP(dst='%s')/"
                                     "UDP(dport=5000, sport=5000)/"
                                     "Raw(load='%s'))\n" % (ns_name, remote_node_ip, remote_pod_ip, message))
        except subprocess.CalledProcessError:
            _log.exception("Failed to send spoofed IPIP packet from scapy")
            return False
        _log.debug("scapy sent spoofed IPIP packet")
        return True

    @staticmethod
    def send_spoofed_vxlan_packet(ns_name, name, remote_node_ip, remote_pod_ip, message):
        try:
            kubectl("exec " + name + " -ti -n %s -- "
                                     "scapy << EOF\n"
                                     "send("
                                     "IP(dst='%s')/"
                                     "UDP(dport=4789)/"
                                     "VXLAN(vni=4096)/"
                                     "Ether()/"
                                     "IP(dst='%s')/"
                                     "UDP(dport=5000, sport=5000)/"
                                     "Raw(load='%s'))\n" % (ns_name, remote_node_ip, remote_pod_ip, message))
        except subprocess.CalledProcessError:
            _log.exception("Failed to send spoofed VXLAN packet from scapy")
            return False
        _log.debug("scapy sent spoofed VXLAN packet")
        return True

    @staticmethod
    def get_pod_ip(podname, ns_name):
        pod = json.loads(kubectl("get po -n %s %s -o json" % (ns_name, podname)))
        return pod["status"]["podIP"]
