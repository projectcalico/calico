// Copyright (c) 2026 Tigera, Inc. All rights reserved.

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

package resources

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kwatch "k8s.io/apimachinery/pkg/watch"
	kubevirtv1 "kubevirt.io/api/core/v1"

	"github.com/projectcalico/calico/libcalico-go/lib/apis/internalapi"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

// VMIMClient provides read access to VirtualMachineInstanceMigration resources
// in a specific namespace. This interface decouples the resources package from
// the kubevirt.io/client-go dependency (whose log package registers a -v flag
// that conflicts with klog in binaries that transitively import this package).
type VMIMClient interface {
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*kubevirtv1.VirtualMachineInstanceMigration, error)
	List(ctx context.Context, opts metav1.ListOptions) (*kubevirtv1.VirtualMachineInstanceMigrationList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (kwatch.Interface, error)
}

func NewLiveMigrationClient(vmimClient func(namespace string) VMIMClient) K8sResourceClient {
	return &LiveMigrationClient{vmimClient: vmimClient}
}

// LiveMigrationClient implements the K8sResourceClient interface for LiveMigration
// resources. LiveMigration is backed by KubeVirt VirtualMachineInstanceMigration
// resources in the Kubernetes datastore.
type LiveMigrationClient struct {
	vmimClient func(namespace string) VMIMClient
}

func (c *LiveMigrationClient) Create(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Create",
		Reason:     "LiveMigration is read-only in the Kubernetes backend",
	}
}

func (c *LiveMigrationClient) Update(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "Update",
		Reason:     "LiveMigration is read-only in the Kubernetes backend",
	}
}

func (c *LiveMigrationClient) Delete(ctx context.Context, key model.Key, revision string, uid *types.UID) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: key,
		Operation:  "Delete",
		Reason:     "LiveMigration is read-only in the Kubernetes backend",
	}
}

func (c *LiveMigrationClient) DeleteKVP(ctx context.Context, kvp *model.KVPair) (*model.KVPair, error) {
	return nil, cerrors.ErrorOperationNotSupported{
		Identifier: kvp.Key,
		Operation:  "DeleteKVP",
		Reason:     "LiveMigration is read-only in the Kubernetes backend",
	}
}

func (c *LiveMigrationClient) Get(ctx context.Context, key model.Key, revision string) (*model.KVPair, error) {
	k := key.(model.ResourceKey)
	vmim, err := c.vmimClient(k.Namespace).Get(ctx, k.Name, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}
	if !vmimShouldEmitLiveMigration(vmim) {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: key}
	}
	return convertVMIMToLiveMigration(vmim), nil
}

func (c *LiveMigrationClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "LiveMigration")
	logContext.Debug("Received List request")
	l := list.(model.ResourceListOptions)

	opts := metav1.ListOptions{ResourceVersion: revision}
	if revision != "" {
		opts.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}

	result, err := c.vmimClient(l.Namespace).List(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}

	kvps := []*model.KVPair{}
	for i := range result.Items {
		if !vmimShouldEmitLiveMigration(&result.Items[i]) {
			continue
		}
		kvps = append(kvps, convertVMIMToLiveMigration(&result.Items[i]))
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: result.ResourceVersion,
	}, nil
}

func (c *LiveMigrationClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	rlo := list.(model.ResourceListOptions)
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sWatch, err := c.vmimClient(rlo.Namespace).Watch(ctx, k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	return newK8sWatcherConverter(ctx, "VirtualMachineInstanceMigration", convertVMIMResourceToLiveMigration, k8sWatch), nil
}

func (c *LiveMigrationClient) EnsureInitialized() error {
	return nil
}

// vmimShouldEmitLiveMigration returns true if the VMIM is in a phase that warrants emitting a
// LiveMigration resource and has the required fields set.  We emit as early as possible (from
// Scheduling phase) so that the TARGET role reaches Felix before or at the same time as the target
// pod's WorkloadEndpoint.  The Source field may be empty in early phases; it will be populated in
// subsequent updates when MigrationState.SourcePod becomes available.
func vmimShouldEmitLiveMigration(vmim *kubevirtv1.VirtualMachineInstanceMigration) bool {
	switch vmim.Status.Phase {
	case kubevirtv1.MigrationScheduling, kubevirtv1.MigrationScheduled,
		kubevirtv1.MigrationPreparingTarget, kubevirtv1.MigrationTargetReady,
		kubevirtv1.MigrationRunning, kubevirtv1.MigrationFailed:
	default:
		return false
	}
	if vmim.Spec.VMIName == "" {
		return false
	}
	if vmim.UID == "" {
		return false
	}
	return true
}

// convertVMIMToLiveMigration converts a KubeVirt VirtualMachineInstanceMigration
// to a Calico LiveMigration KVPair.
func convertVMIMToLiveMigration(vmim *kubevirtv1.VirtualMachineInstanceMigration) *model.KVPair {
	kvp := &model.KVPair{
		Key: model.ResourceKey{
			Kind:      internalapi.KindLiveMigration,
			Namespace: vmim.Namespace,
			Name:      vmim.Name,
		},
		Revision: vmim.ResourceVersion,
	}
	if vmimShouldEmitLiveMigration(vmim) {
		lm := internalapi.NewLiveMigration()
		lm.Name = vmim.Name
		lm.Namespace = vmim.Namespace
		lm.ResourceVersion = vmim.ResourceVersion
		lm.CreationTimestamp = vmim.CreationTimestamp
		lm.UID = vmim.UID
		lm.Labels = vmim.Labels
		lm.Annotations = vmim.Annotations
		// Note: kubevirtv1.MigrationSelectorLabel is "kubevirt.io/vmi-name" but KubeVirt
		// does not set that label on virt-launcher pods.  The actual pod label for the
		// VMI name is "vmi.kubevirt.io/id".
		selector := fmt.Sprintf(
			"%s == '%s' && %s == '%s'",
			"vmi.kubevirt.io/id",
			vmim.Spec.VMIName,
			kubevirtv1.MigrationJobLabel,
			string(vmim.UID),
		)
		lm.Spec = internalapi.LiveMigrationSpec{
			Target: &internalapi.LiveMigrationTarget{
				Selector: &selector,
			},
		}
		// Source is only available once MigrationState is populated (typically from
		// PreparingTarget/TargetReady phase onwards).  In earlier phases we emit without
		// Source so that the TARGET role reaches Felix as early as possible.
		if vmim.Status.MigrationState != nil && vmim.Status.MigrationState.SourcePod != "" {
			lm.Spec.Source = &internalapi.LiveMigrationSource{
				Workload: &internalapi.WorkloadIdentifier{
					OrchestratorID: "k8s",
					WorkloadID:     vmim.Namespace + "/" + vmim.Status.MigrationState.SourcePod,
				},
			}
		}
		kvp.Value = lm
	}
	return kvp
}

// convertVMIMResourceToLiveMigration is a ConvertK8sResourceToKVPair adapter
// for the watch converter.
func convertVMIMResourceToLiveMigration(r Resource) (*model.KVPair, error) {
	return convertVMIMToLiveMigration(r.(*kubevirtv1.VirtualMachineInstanceMigration)), nil
}
