// Copyright (c) 2020-2026 Tigera, Inc. All rights reserved.

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

// Package typhaautoscaler scales a Typha deployment to match a count of the cluster.
package typhaautoscaler

import (
	"context"
	"fmt"
	"time"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	logf "sigs.k8s.io/controller-runtime/pkg/log"

	v3 "github.com/tigera/api/pkg/apis/projectcalico/v3"
	operator "github.com/tigera/operator/api/v1"
	"github.com/tigera/operator/pkg/common"
	"github.com/tigera/operator/pkg/controller/status"
)

var typhaLog = logf.Log.WithName("typha_autoscaler")

const (
	defaultSyncPeriod = 10 * time.Second

	hepCreatedLabelKey   = "projectcalico.org/created-by"
	hepCreatedLabelValue = "calico-kube-controllers"
)

// ReplicaCounter reports how many Typha replicas the cluster needs.
type ReplicaCounter func(ctx context.Context, cli client.Client) (int, error)

// Autoscaler periodically recounts the cluster and, if needed, scales the Typha deployment up/down.
type Autoscaler struct {
	client         client.Client
	deployment     string
	count          ReplicaCounter
	syncPeriod     time.Duration
	statusManager  status.StatusManager
	triggerRunChan chan chan error
	isDegradedChan chan chan bool

	// done is closed when the autoscaler goroutine exits, so callers can wait for shutdown.
	done chan struct{}
}

type Option func(*Autoscaler)

// OptionPeriod is an option that sets a custom sync period for the Typha autoscaler.
func OptionPeriod(syncPeriod time.Duration) Option {
	return func(t *Autoscaler) {
		t.syncPeriod = syncPeriod
	}
}

// New creates a new Typha autoscaler for the named deployment in the calico-system namespace, sized by
// count, optionally applying any options to the default autoscaler instance. The default sync period is 10 seconds.
func New(cli client.Client, deployment string, count ReplicaCounter, statusManager status.StatusManager, options ...Option) *Autoscaler {
	ta := &Autoscaler{
		client:         cli,
		deployment:     deployment,
		count:          count,
		statusManager:  statusManager,
		syncPeriod:     defaultSyncPeriod,
		triggerRunChan: make(chan chan error),
		isDegradedChan: make(chan chan bool),
	}
	for _, option := range options {
		option(ta)
	}
	return ta
}

// Start starts the Typha autoscaler, updating the Typha deployment's replica count every sync period. The triggerRunChan
// can be used to trigger an auto scale run immediately, while the isDegradedChan can be used to get the degraded status
// of the last run. The TriggerRun and IsDegraded functions should be used instead of instead of access these channels directly.
func (t *Autoscaler) Start(ctx context.Context) {
	t.done = make(chan struct{})
	go func() {
		defer close(t.done)
		degraded := false
		ticker := time.NewTicker(t.syncPeriod)
		defer ticker.Stop()
		typhaLog.Info("Starting typha autoscaler", "syncPeriod", t.syncPeriod)

		// Don't autoscale or report degraded if the context has been cancelled - we're shutting down.
		if ctx.Err() != nil {
			typhaLog.Info("typha autoscaler shutting down")
			return
		}

		// Autoscale on start up then do it again every tick.
		if err := t.autoscaleReplicas(ctx); err != nil {
			degraded = true
			typhaLog.Error(err, "Failed to autoscale typha")
			t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, typhaLog)
		}

		for {
			select {
			case <-ticker.C:
				if err := t.autoscaleReplicas(ctx); err != nil {
					degraded = true
					typhaLog.Error(err, "Failed to autoscale typha")

					// Since this run was triggered by the ticker we need to degrade the tigera status now.
					t.statusManager.SetDegraded(operator.ResourceScalingError, fmt.Sprintf("Failed to autoscale typha - %s", err.Error()), nil, typhaLog)
				} else {
					degraded = false
				}
			case errCh := <-t.triggerRunChan:
				if err := t.autoscaleReplicas(ctx); err != nil {
					degraded = true

					// Return the error so the "caller" can decided what to do with the error
					errCh <- err
				} else {
					degraded = false
				}

				close(errCh)

				ticker.Stop()
				ticker = time.NewTicker(t.syncPeriod)
			case boolCh := <-t.isDegradedChan:
				boolCh <- degraded
				close(boolCh)
			case <-ctx.Done():
				typhaLog.Info("typha autoscaler shutting down")
				return
			}
		}
	}()
}

// WaitForShutdown blocks until the autoscaler goroutine started by Start has exited. It is a no-op
// if the autoscaler was never started. Cancel the context passed to Start to trigger shutdown.
func (t *Autoscaler) WaitForShutdown() {
	if t.done != nil {
		<-t.done
	}
}

func (t *Autoscaler) TriggerRun() error {
	errChan := make(chan error)
	t.triggerRunChan <- errChan

	return <-errChan
}

// IsDegraded checks if the last run autoscale run failed and returns true if it did and false otherwise.
func (t *Autoscaler) IsDegraded() bool {
	boolChan := make(chan bool)
	t.isDegradedChan <- boolChan

	return <-boolChan
}

// autoscaleReplicas calculates the number of typha pods that should be running and scales the typha deployment accordingly
func (t *Autoscaler) autoscaleReplicas(ctx context.Context) error {
	expectedReplicas, err := t.count(ctx, t.client)
	if err != nil {
		return err
	}

	if err := t.updateReplicas(ctx, int32(expectedReplicas)); err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("could not scale Typha deployment: %w", err)
	}
	return nil
}

// updateReplicas updates the Typha deployment to the expected replicas if the current replica count differs.
func (t *Autoscaler) updateReplicas(ctx context.Context, expectedReplicas int32) error {
	typha := &appsv1.Deployment{}
	if err := t.client.Get(ctx, types.NamespacedName{Name: t.deployment, Namespace: common.CalicoNamespace}, typha); err != nil {
		return err
	}

	// The replicas field defaults to 1. We need this in case spec.Replicas is nil.
	prevReplicas := int32(1)
	if typha.Spec.Replicas != nil {
		prevReplicas = *typha.Spec.Replicas
	}
	if prevReplicas == expectedReplicas {
		return nil
	}

	typhaLog.Info(fmt.Sprintf("Updating typha replicas from %d to %d", prevReplicas, expectedReplicas))

	// A merge patch carries no resourceVersion precondition, so a stale cached read
	// cannot turn into a write conflict.
	patch := []byte(fmt.Sprintf(`{"spec":{"replicas":%d}}`, expectedReplicas))
	return t.client.Patch(ctx, typha, client.RawPatch(types.MergePatchType, patch))
}

// NodeReplicaCounter sizes Typha by the number of schedulable nodes. Number of replicas
// should be at least (1 typha for every 200 nodes) + 1 but the number of typhas cannot exceed the number of nodes+masters.
func NodeReplicaCounter(ctx context.Context, cli client.Client) (int, error) {
	allSchedulableNodes, linuxNodes, err := nodeCounts(ctx, cli)
	if err != nil {
		return 0, err
	}

	typhaLog.V(5).Info("Number of nodes to consider for typha autoscaling", "all", allSchedulableNodes, "linux", linuxNodes)
	expectedReplicas := common.GetExpectedTyphaScale(allSchedulableNodes)
	if linuxNodes < expectedReplicas {
		return 0, fmt.Errorf("not enough linux nodes to schedule typha pods on, require %d and have %d", expectedReplicas, linuxNodes)
	}
	return expectedReplicas, nil
}

// nodeCounts returns the number of all the schedulable nodes and the number of the schedulable linux nodes. The linux
// node count is needed because typha pods can only be scheduled on linux nodes, however, nodes of other os types (i.e. windows)
// still need to use typha.
func nodeCounts(ctx context.Context, cli client.Client) (int, int, error) {
	nodes := &corev1.NodeList{}
	if err := cli.List(ctx, nodes); err != nil {
		return 0, 0, fmt.Errorf("could not list nodes: %w", err)
	}

	linuxNodes := 0
	schedulable := 0
	for _, n := range nodes.Items {
		if n.Spec.Unschedulable {
			continue
		}

		if _, ok := n.Labels["kubernetes.azure.com/cluster"]; ok && n.Labels["type"] == "virtual-kubelet" {
			// in AKS, there is a feature called 'virtual-nodes' which represent azure's container service as a node in the kubernetes cluster.
			// virtual-nodes have many limitations, and are tainted to prevent pods from running on them.
			// calico-node isn't run there as they don't support hostNetwork or host volume mounts.
			// as such, we shouldn't consider virtual-nodes in the count towards how many typha pods should be run.
			// furthermore, typha can't run on virtual-nodes as it is hostnetworked, so we don't want it's desired
			// replica count to include it.
			continue
		}

		schedulable++
		if n.Labels["kubernetes.io/os"] == "linux" {
			linuxNodes++
		}
	}
	return schedulable, linuxNodes, nil
}

// HostEndpointReplicaCounter sizes Typha by the number of host endpoints that
// calico-kube-controllers did not create.
func HostEndpointReplicaCounter(ctx context.Context, cli client.Client) (int, error) {
	list := &v3.HostEndpointList{}
	if err := cli.List(ctx, list); err != nil {
		return 0, fmt.Errorf("could not list host endpoints: %w", err)
	}

	heps := 0
	for _, hep := range list.Items {
		if hep.Labels[hepCreatedLabelKey] == hepCreatedLabelValue {
			continue
		}

		heps++
	}
	return common.GetExpectedTyphaScale(heps), nil
}
