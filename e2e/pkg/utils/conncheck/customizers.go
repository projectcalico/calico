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

package conncheck

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/test/e2e/framework"
	e2enode "k8s.io/kubernetes/test/e2e/framework/node"

	"github.com/projectcalico/calico/e2e/pkg/utils"
)

// CombineCustomizers is a meta customizer that applies multiple Pod customizers
// to the Pod spec.
func CombineCustomizers(customizers ...func(*corev1.Pod)) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		for _, customizer := range customizers {
			customizer(pod)
		}
	}
}

func UseV4IPPool(poolName string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		if pod.Annotations == nil {
			pod.Annotations = map[string]string{}
		}
		pod.Annotations["cni.projectcalico.org/ipv4pools"] = fmt.Sprintf(`["%s"]`, poolName)
	}
}

// WithNodeName returns a Pod customizer that pins a pod to a specific node.
func WithNodeName(name string) func(*corev1.Pod) {
	return func(pod *corev1.Pod) {
		pod.Spec.NodeName = name
	}
}

// AvoidEachOther is a Pod customizer that adds PodAntiAffinity rules to avoid
// scheduling the Pod on the same node as other Pods deployed with this customizer.
func AvoidEachOther(pod *corev1.Pod) {
	// Include a label which we can use in the anti-affinity rule.
	if pod.Labels == nil {
		pod.Labels = map[string]string{}
	}
	pod.Labels["e2e.projectcalico.org/anti-affinity"] = "true"

	// Add the PodAntiAffinity rule to make sure Pods are scheduled on different nodes.
	pod.Spec.Affinity = &corev1.Affinity{
		PodAntiAffinity: &corev1.PodAntiAffinity{
			RequiredDuringSchedulingIgnoredDuringExecution: []corev1.PodAffinityTerm{
				{
					LabelSelector: &metav1.LabelSelector{
						MatchExpressions: []metav1.LabelSelectorRequirement{
							{
								Key:      "e2e.projectcalico.org/anti-affinity",
								Operator: metav1.LabelSelectorOpIn,
								Values:   []string{"true"},
							},
						},
					},
					TopologyKey: "kubernetes.io/hostname",
				},
			},
		},
	}
}

// WithAvoidControlPlane returns a Pod customizer that keeps the pod off the nodes
// serving kube-apiserver, for specs whose host-level policy would cut the API server
// off. Control-plane nodes are the ones backing the default/kubernetes Service; a
// cluster whose control plane is not in the node list, or has no other ready and
// schedulable node, is left to the scheduler.
func WithAvoidControlPlane(f *framework.Framework) func(*corev1.Pod) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	nodes, err := f.ClientSet.CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	framework.ExpectNoError(err, "failed to list nodes")
	schedulable, err := e2enode.GetReadySchedulableNodes(ctx, f.ClientSet)
	framework.ExpectNoError(err, "failed to list ready schedulable nodes")

	nonControlPlane := sets.New(utils.GetNodesInfo(f, nodes, false).GetNames()...)
	usable := false
	for _, n := range schedulable.Items {
		if nonControlPlane.Has(n.Name) {
			usable = true
			break
		}
	}
	if !usable {
		return func(*corev1.Pod) {}
	}
	var controlPlane []string
	for _, n := range nodes.Items {
		if !nonControlPlane.Has(n.Name) {
			controlPlane = append(controlPlane, n.Name)
		}
	}
	return avoidNodes(controlPlane)
}

// avoidNodes returns a Pod customizer that adds a required node affinity excluding
// the named nodes, alongside any node affinity the pod already has.
func avoidNodes(names []string) func(*corev1.Pod) {
	if len(names) == 0 {
		return func(*corev1.Pod) {}
	}
	notIn := corev1.NodeSelectorRequirement{
		Key:      "metadata.name",
		Operator: corev1.NodeSelectorOpNotIn,
		Values:   names,
	}
	return func(pod *corev1.Pod) {
		if pod.Spec.Affinity == nil {
			pod.Spec.Affinity = &corev1.Affinity{}
		}
		if pod.Spec.Affinity.NodeAffinity == nil {
			pod.Spec.Affinity.NodeAffinity = &corev1.NodeAffinity{}
		}
		na := pod.Spec.Affinity.NodeAffinity
		if na.RequiredDuringSchedulingIgnoredDuringExecution == nil {
			na.RequiredDuringSchedulingIgnoredDuringExecution = &corev1.NodeSelector{}
		}
		terms := na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms
		if len(terms) == 0 {
			na.RequiredDuringSchedulingIgnoredDuringExecution.NodeSelectorTerms = []corev1.NodeSelectorTerm{
				{MatchFields: []corev1.NodeSelectorRequirement{notIn}},
			}
			return
		}
		// Terms are ORed, so every term must exclude the nodes. An empty term matches
		// no node, so it is left alone rather than turned into one that matches.
		for i := range terms {
			if len(terms[i].MatchExpressions) == 0 && len(terms[i].MatchFields) == 0 {
				continue
			}
			terms[i].MatchFields = append(terms[i].MatchFields, notIn)
		}
	}
}
