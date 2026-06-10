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
)

const (
	// TyphaRoleLabel is the pod label the leader Typha applies to its own pod so
	// that the calico-typha-leader headless Service selects it.  Followers
	// discover the leader through that Service.
	TyphaRoleLabel = "projectcalico.org/typha-role"
	// TyphaRoleLeader is the value of TyphaRoleLabel applied by the leader.
	TyphaRoleLeader = "leader"
)

// PodLabeller adds/removes the leader role label on this Typha's own pod via the
// Kubernetes API.  It is used by the role manager (WS-C) so that the leader pod
// is selected by the leader Service.
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

// SetLeaderLabel adds TyphaRoleLabel=leader to our own pod.  Idempotent: a
// strategic-merge patch that sets the label is a no-op if it is already set.
func (l *PodLabeller) SetLeaderLabel(ctx context.Context) error {
	return l.patchRoleLabel(ctx, TyphaRoleLeader)
}

// RemoveLeaderLabel removes TyphaRoleLabel from our own pod.  Idempotent: the
// merge-patch sets the label key to null, which is a no-op if absent.
func (l *PodLabeller) RemoveLeaderLabel(ctx context.Context) error {
	return l.patchRoleLabel(ctx, nil)
}

// patchRoleLabel patches our own pod's TyphaRoleLabel to the given value.  A nil
// value removes the label (JSON null in a strategic-merge patch deletes the
// map entry).
func (l *PodLabeller) patchRoleLabel(ctx context.Context, value any) error {
	patch := map[string]any{
		"metadata": map[string]any{
			"labels": map[string]any{
				TyphaRoleLabel: value,
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
		return fmt.Errorf("failed to patch pod %s/%s role label: %w", l.namespace, l.podName, err)
	}
	log.WithFields(log.Fields{
		"pod":   l.podName,
		"label": TyphaRoleLabel,
		"value": value,
	}).Info("Patched own pod leader role label.")
	return nil
}
