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

package k8s

import (
	"context"
	"encoding/json"
	"fmt"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"

	"github.com/projectcalico/calico/typha/pkg/rolemanager"
)

const (
	// TyphaTierLabel is the pod label that advertises a Typha's hierarchical
	// tier.  The pod template sets it to TyphaTier2 ("2") for every Typha; the
	// role manager patches it to TyphaTierLeader/TyphaTier1 on promotion and back
	// to TyphaTier2 on demotion.  The per-tier Services select on this label:
	//
	//   calico-typha-leader  selects typha-tier=leader
	//   calico-typha-tier1   selects typha-tier=1
	//
	// and the discovery code cross-references the tier Services against the main
	// calico-typha Service to classify each endpoint's tier.
	TyphaTierLabel = "projectcalico.org/typha-tier"

	// TyphaTierLeader / TyphaTier1 / TyphaTier2 are the values of TyphaTierLabel.
	TyphaTierLeader = "leader"
	TyphaTier1      = "1"
	TyphaTier2      = "2"
)

// PodLabeller patches the tier label on this Typha's own pod via the Kubernetes
// API.  It is used by the role manager so that the leader / tier-1 pods are
// selected by their respective Services.  It patches only its own pod name (the
// shared-ServiceAccount pods:patch grant is documented in DESIGN.md).
type PodLabeller struct {
	client    kubernetes.Interface
	namespace string
	podName   string
}

// NewPodLabeller constructs a PodLabeller for the given pod.  podName and
// namespace are this Typha's own pod identity (injected via the downward API).
func NewPodLabeller(client kubernetes.Interface, namespace, podName string) *PodLabeller {
	return &PodLabeller{
		client:    client,
		namespace: namespace,
		podName:   podName,
	}
}

// SetTierLabel patches our own pod's tier label to the value implied by role.
// Implements rolemanager.Labeller.
func (l *PodLabeller) SetTierLabel(ctx context.Context, role rolemanager.Role) error {
	return l.patchTierLabel(ctx, TierLabelValue(role))
}

// TierLabelValue maps a role-manager Role to the TyphaTierLabel value.  Sourceless
// (only seen transiently at shutdown) maps to tier-2, the safe leaf value.
func TierLabelValue(role rolemanager.Role) string {
	switch role {
	case rolemanager.Leader:
		return TyphaTierLeader
	case rolemanager.Tier1:
		return TyphaTier1
	default:
		return TyphaTier2
	}
}

// patchTierLabel patches our own pod's TyphaTierLabel to the given value via a
// strategic-merge patch (idempotent — a no-op if already set).
func (l *PodLabeller) patchTierLabel(ctx context.Context, value string) error {
	patch := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				TyphaTierLabel: value,
			},
		},
	}
	body, err := json.Marshal(patch)
	if err != nil {
		return fmt.Errorf("failed to marshal pod label patch: %w", err)
	}
	_, err = l.client.CoreV1().Pods(l.namespace).Patch(
		ctx,
		l.podName,
		types.StrategicMergePatchType,
		body,
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to patch pod %s/%s tier label: %w", l.namespace, l.podName, err)
	}
	log.WithFields(log.Fields{
		"pod":   l.podName,
		"label": TyphaTierLabel,
		"value": value,
	}).Info("Patched own pod tier label.")
	return nil
}
