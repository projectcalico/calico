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

// This is a kind-only system test asserting that Calico drops
// IPIP- and VXLAN-encapsulated packets whose inner source is spoofed. A scapy
// pod on one node forges an encapsulated packet addressed to a pod on another
// node; Calico's anti-spoofing enforcement must prevent the inner packet from
// being delivered, while a normal (un-encapsulated, un-spoofed) packet is.

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

	e2eutils "github.com/projectcalico/calico/e2e/pkg/utils"
	"github.com/projectcalico/calico/node/tests/k8st/utils"
)

const (
	// spoofedNodeIP is the (arbitrary, in-pod-CIDR) address used as the outer
	// destination of forged encapsulated packets. Matches the Python original.
	spoofedNodeIP = "10.192.0.3"

	// defaultV4Pool is the cluster's default IPv4 IPPool, whose encapsulation
	// the operator reconciles in response to Installation patches.
	defaultV4Pool = "default-ipv4-ippool"
)

// TestSpoof creates an access (UDP sink) pod and a scapy (packet forger) pod on
// two different worker nodes, then runs the IPIP and VXLAN anti-spoofing
// scenarios. The pods and namespace are shared across both scenarios; each
// scenario flips the cluster encapsulation to the mode under test. The
// scenarios mutate cluster-wide encapsulation, so they run sequentially.
func TestSpoof(t *testing.T) {
	defer utils.CollectDiagsOnFailure(t)()

	// nsName holds the access/scapy pod pair shared by both scenarios.
	nsName := e2eutils.GenerateRandomName("ipip-spoofing")

	g := NewWithT(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	t.Cleanup(cancel)

	cli := newClient(g)

	nodes, _, _ := utils.NodeInfo(t)
	g.Expect(len(nodes)).To(BeNumerically(">=", 3),
		"spoofing test needs a control-plane node and at least two workers")

	// Namespace + pods, created once for both scenarios.
	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: nsName}}
	g.Expect(cli.Create(ctx, ns)).To(Succeed(), "creating namespace")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), ns) })

	// Restore the cluster to IPIP encapsulation when the whole test is done,
	// matching the Python tearDownClass.
	t.Cleanup(func() { setEncapsulation(t, g, cli, context.Background(), "IPIP") })

	// access listens for UDP on 5000 and appends what it receives to snoop.txt;
	// the grep against that file is how we detect delivery.
	access := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: nsName},
		Spec: corev1.PodSpec{
			NodeName: nodes[1],
			Containers: []corev1.Container{{
				Name:    "access",
				Image:   "busybox",
				Command: []string{"/bin/sh", "-c", "nc -l -u -p 5000 &> /root/snoop.txt"},
			}},
		},
	}
	g.Expect(cli.Create(ctx, access)).To(Succeed(), "creating access pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), access) })

	// scapy forges the (normal and spoofed) packets.
	scapy := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "scapy", Namespace: nsName},
		Spec: corev1.PodSpec{
			NodeName: nodes[2],
			Containers: []corev1.Container{{
				Name:    "scapy",
				Image:   "calico/scapy:v2.4.0",
				Command: []string{"/bin/sleep", "3600"},
			}},
		},
	}
	g.Expect(cli.Create(ctx, scapy)).To(Succeed(), "creating scapy pod")
	t.Cleanup(func() { _ = cli.Delete(context.Background(), scapy) })

	utils.WaitForPodReady(t, nsName, "scapy", 2*time.Minute)
	utils.WaitForPodReady(t, nsName, "access", 2*time.Minute)

	// IPIP: a packet of the form IP(node)/IP(pod)/UDP is IPIP encapsulation.
	t.Run("ipip", func(t *testing.T) {
		defer utils.CollectDiagsOnFailure(t)()
		runSpoofScenario(t, cli, ctx, nsName, "IPIP", "ipip", func(g *WithT, podIP, message string) {
			sendScapy(t, nsName, fmt.Sprintf(
				"send(IP(dst='%s')/IP(dst='%s')/UDP(dport=5000, sport=5000)/Raw(load='%s'))",
				spoofedNodeIP, podIP, message))
		})
	})

	// VXLAN: IP(node)/UDP(4789)/VXLAN/Ether()/IP(pod)/UDP is VXLAN encapsulation.
	t.Run("vxlan", func(t *testing.T) {
		defer utils.CollectDiagsOnFailure(t)()
		runSpoofScenario(t, cli, ctx, nsName, "VXLAN", "vxlan", func(g *WithT, podIP, message string) {
			sendScapy(t, nsName, fmt.Sprintf(
				"send(IP(dst='%s')/UDP(dport=4789)/VXLAN(vni=4096)/Ether()/IP(dst='%s')/UDP(dport=5000, sport=5000)/Raw(load='%s'))",
				spoofedNodeIP, podIP, message))
		})
	})
}

// runSpoofScenario sets the requested encapsulation, confirms a normal packet
// is delivered, then confirms a spoofed (encapsulated, forged-inner-source)
// packet is not. sendSpoofed forges the encapsulated packet for the mode under
// test (its shape is the only thing that differs between IPIP and VXLAN).
func runSpoofScenario(t *testing.T, cli ctrlclient.Client, ctx context.Context, nsName, encap, prefix string, sendSpoofed func(g *WithT, podIP, message string)) {
	g := NewWithT(t)

	setEncapsulation(t, g, cli, ctx, encap)

	// The access pod's IP is the inner destination of every packet we forge.
	remotePodIP := waitForPodIP(ctx, g, cli, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "access", Namespace: nsName},
	}, corev1.IPv4Protocol)
	t.Logf("access pod IP: %s", remotePodIP)

	// A normal pod-to-pod packet must be delivered.
	clearConntrack(t, ctx)
	normalMsg := prefix + "-normal"
	g.Eventually(func() error {
		sendScapy(t, nsName, fmt.Sprintf(
			"send(IP(dst='%s')/UDP(dport=5000, sport=5000)/Raw(load='%s'))", remotePodIP, normalMsg))
		return grepSnoop(t, nsName, normalMsg)
	}, "60s", "2s").Should(Succeed(), "normal %s packet was never delivered", encap)

	// A spoofed (encapsulated) packet must NOT be delivered: we keep forging it
	// and require that the grep for its payload keeps failing.
	clearConntrack(t, ctx)
	spoofedMsg := prefix + "-spoofed"
	g.Eventually(func() error {
		sendSpoofed(g, remotePodIP, spoofedMsg)
		if err := grepSnoop(t, nsName, spoofedMsg); err == nil {
			return fmt.Errorf("ERROR - succeeded in sending spoofed %s packet", encap)
		}
		return nil
	}, "60s", "2s").Should(Succeed(), "spoofed %s packet was delivered — anti-spoofing failed", encap)
}

// sendScapy feeds a single scapy send() statement to the scapy pod on stdin.
// scapy send failures are non-fatal (the Python original swallowed them): the
// assertion is made by grepping the access pod, not by scapy's exit code.
func sendScapy(t *testing.T, nsName, script string) {
	t.Helper()
	_, _ = utils.ExecInPodStdin(t, nsName, "scapy", script+"\n", []string{"scapy"},
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
}

// grepSnoop greps the access pod's capture file for message. A non-nil error
// means the message was not found (i.e. the packet was not delivered).
func grepSnoop(t *testing.T, nsName, message string) error {
	t.Helper()
	_, err := utils.ExecInPod(t, nsName, "access", "grep "+message+" /root/snoop.txt",
		utils.RunOptions{AllowFail: true, SuppressErrLog: true})
	return err
}

// clearConntrack flushes the conntrack table in every calico-node pod so a
// previous delivery can't mask the next test via an established flow.
func clearConntrack(t *testing.T, ctx context.Context) {
	t.Helper()
	cs := utils.K8sClient(t)
	pods, err := cs.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err != nil {
		t.Fatalf("listing calico-node pods: %v", err)
	}
	for _, p := range pods.Items {
		utils.MustExecInCalicoNode(t, p.Spec.NodeName, "conntrack -F")
	}
}

// setEncapsulation flips the cluster's encapsulation by patching the operator
// Installation, waits for the operator to reconcile the default IPv4 pool, then
// restarts the calico-node pods so the change takes effect cleanly. It is a
// no-op (beyond the pool read) when already in the requested mode.
func setEncapsulation(t *testing.T, g *WithT, cli ctrlclient.Client, ctx context.Context, encap string) {
	t.Helper()

	var wantIPIP v3.IPIPMode
	var wantVXLAN v3.VXLANMode
	switch encap {
	case "IPIP":
		wantIPIP, wantVXLAN = v3.IPIPModeAlways, v3.VXLANModeNever
	case "VXLAN":
		wantIPIP, wantVXLAN = v3.IPIPModeNever, v3.VXLANModeAlways
	default:
		t.Fatalf("unsupported encapsulation %q", encap)
	}

	pool := &v3.IPPool{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: defaultV4Pool}, pool)).
		To(Succeed(), "reading %s", defaultV4Pool)
	if pool.Spec.IPIPMode == wantIPIP && pool.Spec.VXLANMode == wantVXLAN {
		t.Logf("Encapsulation already set to %s, skipping", encap)
		return
	}

	t.Logf("Setting encapsulation to %s via Installation", encap)
	wantEncap := map[string]operatorv1.EncapsulationType{
		"IPIP":  operatorv1.EncapsulationIPIP,
		"VXLAN": operatorv1.EncapsulationVXLAN,
	}[encap]

	inst := &operatorv1.Installation{}
	g.Expect(cli.Get(ctx, ctrlclient.ObjectKey{Name: "default"}, inst)).
		To(Succeed(), "reading Installation default")
	g.Expect(inst.Spec.CalicoNetwork).NotTo(BeNil(), "Installation has no calicoNetwork")
	g.Expect(inst.Spec.CalicoNetwork.IPPools).NotTo(BeEmpty(), "Installation has no calicoNetwork.ipPools")

	patch := ctrlclient.MergeFrom(inst.DeepCopy())
	inst.Spec.CalicoNetwork.IPPools[0].Encapsulation = wantEncap
	g.Expect(cli.Patch(ctx, inst, patch)).
		To(Succeed(), "patching Installation encapsulation to %s", encap)

	// Wait for the operator to reconcile the IPPool before restarting pods.
	g.Eventually(func() error {
		p := &v3.IPPool{}
		if err := cli.Get(ctx, ctrlclient.ObjectKey{Name: defaultV4Pool}, p); err != nil {
			return err
		}
		if p.Spec.IPIPMode != wantIPIP || p.Spec.VXLANMode != wantVXLAN {
			return fmt.Errorf("IPPool not yet reconciled: ipipMode=%s vxlanMode=%s",
				p.Spec.IPIPMode, p.Spec.VXLANMode)
		}
		return nil
	}, "60s", "2s").Should(Succeed(), "operator did not reconcile %s to %s", defaultV4Pool, encap)

	// Restart calico-node to cleanly apply the new encapsulation.
	cs := utils.K8sClient(t)
	g.Expect(cs.CoreV1().Pods("calico-system").DeleteCollection(ctx, metav1.DeleteOptions{},
		metav1.ListOptions{LabelSelector: "k8s-app=calico-node"})).
		To(Succeed(), "deleting calico-node pods")
	waitForCalicoNodeRestart(t, ctx)
}

// waitForCalicoNodeRestart blocks until every calico-node pod is freshly
// running and Ready, with none still terminating. This is stricter than a bare
// readiness wait: right after DeleteCollection the old pods may still report
// Ready, so we additionally require no pod carries a deletion timestamp.
func waitForCalicoNodeRestart(t *testing.T, ctx context.Context) {
	t.Helper()

	cs := utils.K8sClient(t)
	err := utils.RetryUntilSuccess(t, 2*time.Minute, func() error {
		pods, err := cs.CoreV1().Pods("calico-system").List(ctx, metav1.ListOptions{
			LabelSelector: "k8s-app=calico-node",
		})
		if err != nil {
			return err
		}
		if len(pods.Items) == 0 {
			return fmt.Errorf("no calico-node pods yet")
		}
		for _, p := range pods.Items {
			if p.DeletionTimestamp != nil {
				return fmt.Errorf("calico-node pod %s is still terminating", p.Name)
			}
			ready := false
			for _, c := range p.Status.Conditions {
				if c.Type == corev1.PodReady && c.Status == corev1.ConditionTrue {
					ready = true
				}
			}
			if !ready {
				return fmt.Errorf("calico-node pod %s is not ready", p.Name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("calico-node pods did not restart cleanly: %v", err)
	}
}
