// Copyright (c) 2026 Tigera, Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// ipip_spoofing_test.go is the Go port of test_ipip_spoofing.py. It confirms
// that Calico's anti-spoofing rules drop encapsulated (IPIP / VXLAN) packets
// whose inner source is forged: a normal pod-to-pod packet must be delivered,
// but a hand-crafted spoofed packet sent via scapy must be dropped.

package k8stests

import (
	"context"
	"fmt"
	"testing"
	"time"

	. "github.com/onsi/gomega"
	v3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	operatorv1 "github.com/tigera/operator/api/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

// The fake outer IP the spoofed packets are addressed to. Kept identical to
// the Python test so the spoof scenario is unchanged.
const spoofRemoteNodeIP = "10.192.0.3"

// TestSpoof creates a UDP listener pod ("access") and a scapy sender pod
// ("scapy") on two different nodes, then for both IPIP and VXLAN encapsulation
// asserts that a normal packet is delivered while a spoofed one is dropped.
// Port of test_ipip_spoofing.py:TestSpoof.
func TestSpoof(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	g := NewWithT(t)
	cli := newClient(g)

	nsName := utils.GenerateUniqueID(t, 5, "spoof")
	utils.CreateNamespace(t, nsName)
	t.Cleanup(func() {
		utils.DeleteNamespaceAndConfirm(t, nsName)
		// Restore the cluster to IPIP encapsulation for subsequent suites.
		setEncapsulation(t, g, cli, "IPIP")
	})

	nodes, _, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3), "need a control-plane node and two workers")

	// access listens for UDP on 5000 and records everything it receives to a
	// file we later grep. scapy idles so we can exec crafted sends in it.
	utils.NewPod(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: nsName},
		Spec: corev1.PodSpec{
			NodeName: nodes[1],
			Containers: []corev1.Container{{
				Name:    "access",
				Image:   "busybox",
				Command: []string{"/bin/sh", "-c", "nc -l -u -p 5000 &> /root/snoop.txt"},
			}},
		},
	})
	utils.NewPod(t, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "scapy", Namespace: nsName},
		Spec: corev1.PodSpec{
			NodeName: nodes[2],
			Containers: []corev1.Container{{
				Name:    "scapy",
				Image:   "calico/scapy:v2.4.0",
				Command: []string{"/bin/sleep", "3600"},
			}},
		},
	})
	utils.WaitForPodReady(t, nsName, "scapy", 2*time.Minute)
	utils.WaitForPodReady(t, nsName, "access", 2*time.Minute)

	t.Run("ipip", func(t *testing.T) {
		defer utils.CollectDiagsOnFailure(t)()
		runSpoofScenario(t, NewWithT(t), cli, nsName, "IPIP", "ipip-normal", "ipip-spoofed", sendSpoofedIPIP)
	})

	t.Run("vxlan", func(t *testing.T) {
		defer utils.CollectDiagsOnFailure(t)()
		runSpoofScenario(t, NewWithT(t), cli, nsName, "VXLAN", "vxlan-normal", "vxlan-spoofed", sendSpoofedVXLAN)
	})
}

// runSpoofScenario sets the encapsulation, confirms a normal pod-to-pod packet
// is delivered, then confirms a spoofed packet is dropped.
func runSpoofScenario(t *testing.T, g *WithT, cli ctrlclient.Client, ns, encap, normalMsg, spoofMsg string,
	sendSpoofed func(t *testing.T, ns, remotePodIP, msg string),
) {
	setEncapsulation(t, g, cli, encap)

	// Look up the listener pod's IP.
	var remotePodIP string
	g.Eventually(func() error {
		pod, err := utils.K8sClient(t).CoreV1().Pods(ns).Get(context.Background(), "access", metav1.GetOptions{})
		if err != nil {
			return err
		}
		remotePodIP = pod.Status.PodIP
		if remotePodIP == "" {
			return fmt.Errorf("access pod has no IP yet")
		}
		return nil
	}, "30s", "1s").Should(Succeed())
	t.Logf("access pod IP: %s", remotePodIP)

	// A normal pod-to-pod packet must be delivered.
	clearConntrack(t)
	g.Eventually(func() error {
		sendPacket(t, ns, remotePodIP, normalMsg)
		_, err := utils.ExecInPod(t, ns, "access", "grep "+normalMsg+" /root/snoop.txt",
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		return err
	}, "90s", "3s").Should(Succeed(), "normal packet %q was never received", normalMsg)

	// A spoofed packet must be dropped: the listener must never record it.
	clearConntrack(t)
	g.Eventually(func() error {
		sendSpoofed(t, ns, remotePodIP, spoofMsg)
		_, err := utils.ExecInPod(t, ns, "access", "grep "+spoofMsg+" /root/snoop.txt",
			utils.RunOptions{AllowFail: true, SuppressErrLog: true})
		if err == nil {
			return fmt.Errorf("spoofed packet %q was received — anti-spoofing failed", spoofMsg)
		}
		return nil
	}, "90s", "3s").Should(Succeed())
}

// setEncapsulation switches the default IPv4 pool's encapsulation by patching
// the operator Installation, waits for the IPPool to reconcile, and restarts
// calico-node. No-op if the pool is already in the requested mode. Mirrors
// TestSpoof._set_encapsulation.
func setEncapsulation(t testing.TB, g *WithT, cli ctrlclient.Client, encap string) {
	t.Helper()

	var wantIPIP v3.IPIPMode
	var wantVXLAN v3.VXLANMode
	var encapType operatorv1.EncapsulationType
	switch encap {
	case "IPIP":
		wantIPIP, wantVXLAN, encapType = v3.IPIPModeAlways, v3.VXLANModeNever, operatorv1.EncapsulationIPIP
	case "VXLAN":
		wantIPIP, wantVXLAN, encapType = v3.IPIPModeNever, v3.VXLANModeAlways, operatorv1.EncapsulationVXLAN
	default:
		t.Fatalf("unknown encapsulation %q", encap)
	}

	poolReconciled := func() error {
		pool := &v3.IPPool{}
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default-ipv4-ippool"}, pool); err != nil {
			return err
		}
		if pool.Spec.IPIPMode != wantIPIP || pool.Spec.VXLANMode != wantVXLAN {
			return fmt.Errorf("IPPool not reconciled: ipipMode=%s vxlanMode=%s", pool.Spec.IPIPMode, pool.Spec.VXLANMode)
		}
		return nil
	}

	if poolReconciled() == nil {
		t.Logf("Encapsulation already set to %s, skipping", encap)
		return
	}

	t.Logf("Setting encapsulation to %s via Installation", encap)
	err := utils.RetryUntilSuccess(t, 30*time.Second, func() error {
		inst := &operatorv1.Installation{}
		if err := cli.Get(context.Background(), ctrlclient.ObjectKey{Name: "default"}, inst); err != nil {
			return err
		}
		if inst.Spec.CalicoNetwork == nil || len(inst.Spec.CalicoNetwork.IPPools) == 0 {
			return fmt.Errorf("Installation has no calicoNetwork ipPools")
		}
		inst.Spec.CalicoNetwork.IPPools[0].Encapsulation = encapType
		return cli.Update(context.Background(), inst)
	})
	g.Expect(err).NotTo(HaveOccurred(), "patching Installation encapsulation")

	// Wait for the operator to reconcile the IPPool before restarting pods.
	g.Eventually(poolReconciled, "60s", "2s").Should(Succeed())

	// Restart calico-node so the new encapsulation is cleanly applied.
	restartCalicoNode(t)
}

// restartCalicoNode deletes every calico-node pod and waits for the
// replacements to become ready.
func restartCalicoNode(t testing.TB) {
	t.Helper()
	cs := utils.K8sClient(t)
	pods, err := cs.CoreV1().Pods("calico-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err != nil {
		t.Fatalf("listing calico-node pods: %v", err)
	}
	for _, p := range pods.Items {
		if err := cs.CoreV1().Pods("calico-system").Delete(context.Background(), p.Name, metav1.DeleteOptions{}); err != nil {
			t.Logf("deleting calico-node pod %s: %v", p.Name, err)
		}
	}
	utils.WaitForPodsReady(t, "calico-system", "k8s-app=calico-node", 2*time.Minute)
}

// clearConntrack flushes the conntrack table in every calico-node pod. Mirrors
// TestSpoof.clear_conntrack.
func clearConntrack(t *testing.T) {
	t.Helper()
	cs := utils.K8sClient(t)
	pods, err := cs.CoreV1().Pods("calico-system").List(context.Background(), metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err != nil {
		t.Fatalf("listing calico-node pods: %v", err)
	}
	for _, p := range pods.Items {
		utils.MustExecInPod(t, "calico-system", p.Name, "conntrack -F")
	}
}

// sendPacket sends a normal UDP packet to remotePodIP via scapy. Mirrors
// TestSpoof.send_packet.
func sendPacket(t *testing.T, ns, remotePodIP, message string) {
	t.Helper()
	script := fmt.Sprintf("send(IP(dst='%s')/UDP(dport=5000, sport=5000)/Raw(load='%s'))\n", remotePodIP, message)
	runScapy(t, ns, script)
}

// sendSpoofedIPIP sends an IPIP-encapsulated packet with a forged inner source.
// Mirrors TestSpoof.send_spoofed_ipip_packet.
func sendSpoofedIPIP(t *testing.T, ns, remotePodIP, message string) {
	t.Helper()
	script := fmt.Sprintf("send(IP(dst='%s')/IP(dst='%s')/UDP(dport=5000, sport=5000)/Raw(load='%s'))\n",
		spoofRemoteNodeIP, remotePodIP, message)
	runScapy(t, ns, script)
}

// sendSpoofedVXLAN sends a VXLAN-encapsulated packet with a forged inner
// source. Mirrors TestSpoof.send_spoofed_vxlan_packet.
func sendSpoofedVXLAN(t *testing.T, ns, remotePodIP, message string) {
	t.Helper()
	script := fmt.Sprintf("send(IP(dst='%s')/UDP(dport=4789)/VXLAN(vni=4096)/Ether()/IP(dst='%s')/UDP(dport=5000, sport=5000)/Raw(load='%s'))\n",
		spoofRemoteNodeIP, remotePodIP, message)
	runScapy(t, ns, script)
}

// runScapy feeds a one-line scapy script to the scapy pod over stdin (the
// client-go equivalent of `kubectl exec scapy -ti -- scapy <<EOF ...`).
func runScapy(t *testing.T, ns, script string) {
	t.Helper()
	if _, err := utils.ExecInPodStdin(t, ns, "scapy", []string{"scapy"}, script); err != nil {
		// A scapy send failing to execute is logged but not fatal; the
		// delivery assertions (grep) determine pass/fail.
		t.Logf("scapy send returned error (continuing): %v", err)
	}
}
