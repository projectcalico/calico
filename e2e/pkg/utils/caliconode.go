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

package utils

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	e2ekubectl "k8s.io/kubernetes/test/e2e/framework/kubectl"
)

// GetCalicoNodePodOnNode returns the calico-node pod running on the given node.
func GetCalicoNodePodOnNode(clientset kubernetes.Interface, nodeName string) *corev1.Pod {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	podList, err := clientset.CoreV1().Pods(metav1.NamespaceAll).List(ctx, metav1.ListOptions{
		LabelSelector: "k8s-app=calico-node",
	})
	if err != nil {
		logrus.WithError(err).Error("Failed to list calico-node pods")
		return nil
	}
	for i := range podList.Items {
		if podList.Items[i].Spec.NodeName == nodeName {
			return &podList.Items[i]
		}
	}
	return nil
}

// GetPodInterfaceName returns the host-side veth interface name for a workload pod
// by running `ip route get <podIP>` in the calico-node container. This is
// prefix-agnostic and works with cali, eni, azv, gke, or any other prefix.
func GetPodInterfaceName(calicoNodePod *corev1.Pod, workloadPodIP string) string {
	cmd := fmt.Sprintf("ip route get %s", workloadPodIP)
	out, err := ExecInCalicoNode(calicoNodePod, cmd)
	if err != nil {
		logrus.WithError(err).WithField("cmd", cmd).Error("Failed to exec ip route get in calico-node pod")
		return ""
	}

	// Output format: "<IP> dev <IFACE> scope link src <SRC>"
	fields := strings.Fields(out)
	for i, f := range fields {
		if f == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	logrus.WithField("output", out).Error("Could not parse interface name from ip route get output")
	return ""
}

// GetPodInterfaceIndex returns the interface index for the given interface name
// by running `ip addr` in the calico-node container.
func GetPodInterfaceIndex(calicoNodePod *corev1.Pod, intfName string) int {
	cmd := fmt.Sprintf("ip addr | grep '%s' | sed -n 's/^\\([0-9]\\+\\):.*/\\1/p'", intfName)
	out, err := ExecInCalicoNode(calicoNodePod, cmd)
	if err != nil {
		logrus.WithError(err).WithField("cmd", cmd).Error("Failed to exec ip addr in calico-node pod")
		return 0
	}
	idx, err := strconv.Atoi(strings.TrimSpace(out))
	if err != nil {
		logrus.WithError(err).WithField("output", out).Error("Failed to parse interface index")
		return 0
	}
	return idx
}

// ExecInCalicoNode runs a shell command in a calico-node pod via kubectl exec.
func ExecInCalicoNode(pod *corev1.Pod, cmd string) (string, error) {
	args := []string{"exec", pod.Name, "-n", pod.Namespace, "--", "sh", "-c", cmd}
	return e2ekubectl.NewKubectlCommand(pod.Namespace, args...).
		WithTimeout(time.After(10 * time.Second)).
		Exec()
}
