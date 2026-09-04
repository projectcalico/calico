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

// Package nodestatus holds the taint and node condition vocabulary shared between
// calico-node and kube-controllers, which both write node status.
package nodestatus

import (
	"os"

	corev1 "k8s.io/api/core/v1"
)

const (
	// NetworkReadyTaintKey keeps workloads off a node until Calico networking is ready.
	NetworkReadyTaintKey = "node.projectcalico.org/network-not-ready"

	// NetworkReadyTaintEnvVar gates *adding* the taint. Removal is unconditional, so turning the
	// feature off drains the taint from nodes that already carry it.
	NetworkReadyTaintEnvVar = "CALICO_MANAGE_NETWORK_READY_TAINT"
)

// Reason and message pairs for the NetworkUnavailable condition. The condition shows up in
// `kubectl describe node`, so the message says which of the three situations produced it.
const (
	NetworkReadyReason   = "CalicoIsUp"
	NetworkReadyMessage  = "Calico is running on this node"
	NetworkDownReason    = "CalicoIsDown"
	NetworkDownShutdown  = "Calico is shutting down on this node"
	NetworkDownUnhealthy = "Calico node health checks are failing on this node"
)

// AddNetworkReadyTaintEnabled reports whether the operator asked us to add the network-ready taint.
func AddNetworkReadyTaintEnabled() bool {
	return os.Getenv(NetworkReadyTaintEnvVar) == "true"
}

// HasNetworkReadyTaint reports whether the node currently carries the network-ready taint.
func HasNetworkReadyTaint(node *corev1.Node) bool {
	for _, t := range node.Spec.Taints {
		if t.Key == NetworkReadyTaintKey {
			return true
		}
	}
	return false
}

// WithoutNetworkReadyTaint returns the node's taints with the network-ready taint removed.
func WithoutNetworkReadyTaint(taints []corev1.Taint) []corev1.Taint {
	kept := make([]corev1.Taint, 0, len(taints))
	for _, t := range taints {
		if t.Key == NetworkReadyTaintKey {
			continue
		}
		kept = append(kept, t)
	}
	return kept
}

// OwnsNetworkUnavailable reports whether Calico set the node's current NetworkUnavailable
// condition. Cloud route controllers write the same condition, and clearing theirs would claim
// a node is routable while its cloud routes are still missing.
func OwnsNetworkUnavailable(node *corev1.Node) bool {
	for _, cond := range node.Status.Conditions {
		if cond.Type != corev1.NodeNetworkUnavailable {
			continue
		}
		return cond.Reason == NetworkReadyReason || cond.Reason == NetworkDownReason
	}
	return false
}

// NetworkUnavailable returns the node's current NetworkUnavailable status, defaulting to False
// for a node that has never had the condition set.
func NetworkUnavailable(node *corev1.Node) corev1.ConditionStatus {
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeNetworkUnavailable {
			return cond.Status
		}
	}
	return corev1.ConditionFalse
}
