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

//go:build pickerdemo

// Command pickerdemo is a developer tool to eyeball the cluster-diags
// interactive node picker against a fake cluster of arbitrary size, with no real
// Kubernetes needed. It is compiled only under the `pickerdemo` build tag, so it
// never ships in the calico binary.
//
//	go run -tags pickerdemo ./calicoctl/calicoctl/commands/cluster/cmd/pickerdemo
//	go run -tags pickerdemo ./calicoctl/calicoctl/commands/cluster/cmd/pickerdemo -nodes 5000
package main

import (
	"flag"
	"fmt"
	"os"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/projectcalico/calico/calicoctl/calicoctl/commands/cluster"
)

func main() {
	nodes := flag.Int("nodes", 5000, "number of fake nodes to simulate")
	pods := flag.Int("pods", 50, "number of fake pods to simulate (for the by-pod path)")
	flag.Parse()

	zones := []string{"us-east-1a", "us-east-1b", "us-east-1c", "us-west-2a"}

	// EKS-style node names: ip-<private-ip>.<region>.compute.internal.
	nodeName := func(i int) string {
		zone := zones[i%len(zones)]
		region := zone[:len(zone)-1] // drop the AZ letter
		return fmt.Sprintf("ip-10-%d-%d-%d.%s.compute.internal",
			(i/65536)%256, (i/256)%256, i%256, region)
	}

	objs := make([]runtime.Object, 0, *nodes+*pods)
	for i := 0; i < *nodes; i++ {
		labels := map[string]string{
			"topology.kubernetes.io/zone": zones[i%len(zones)],
		}
		// Sprinkle in some control-plane and worker roles.
		switch {
		case i%50 == 0:
			labels["node-role.kubernetes.io/control-plane"] = ""
		default:
			labels["node-role.kubernetes.io/worker"] = ""
		}
		// Mark every 20th node NotReady so the readiness column varies.
		ready := corev1.ConditionTrue
		if i%20 == 0 {
			ready = corev1.ConditionFalse
		}
		objs = append(objs, &corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: nodeName(i), Labels: labels},
			Status: corev1.NodeStatus{
				Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: ready}},
			},
		})
	}
	podNamespaces := []string{"calico-system", "kube-system", "default", "batch"}
	for i := 0; i < *pods; i++ {
		// Vary the phase so finished pods (Succeeded/Failed) show up alongside
		// running ones in the picker.
		phase := corev1.PodRunning
		switch {
		case i%7 == 0:
			phase = corev1.PodSucceeded
		case i%11 == 0:
			phase = corev1.PodFailed
		}
		objs = append(objs, &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: podNamespaces[i%len(podNamespaces)],
				Name:      fmt.Sprintf("workload-%05d", i),
			},
			Spec:   corev1.PodSpec{NodeName: nodeName(i)},
			Status: corev1.PodStatus{Phase: phase},
		})
	}

	client := fake.NewSimpleClientset(objs...)
	fmt.Printf("Simulating %d nodes and %d pods.\n", *nodes, *pods)

	problem, comparison, proceed, err := cluster.RunInteractiveSelectionDemo(client)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
	if !proceed {
		fmt.Println("Cancelled — no selection made.")
		return
	}
	fmt.Println("Problem nodes:   ", problem)
	fmt.Println("Comparison nodes:", comparison)
}
