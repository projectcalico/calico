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
	"reflect"

	log "github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	kwatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"

	libapiv3 "github.com/projectcalico/calico/libcalico-go/lib/apis/v3"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
	cerrors "github.com/projectcalico/calico/libcalico-go/lib/errors"
)

var vmimGVR = schema.GroupVersionResource{
	Group:    "kubevirt.io",
	Version:  "v1",
	Resource: "virtualmachineinstancemigrations",
}

func NewLiveMigrationClient(dynClient dynamic.Interface) K8sResourceClient {
	return &LiveMigrationClient{dynClient: dynClient}
}

// LiveMigrationClient implements the K8sResourceClient interface for LiveMigration
// resources. LiveMigration is backed by KubeVirt VirtualMachineInstanceMigration
// resources in the Kubernetes datastore.
type LiveMigrationClient struct {
	dynClient dynamic.Interface
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
	u, err := c.dynClient.Resource(vmimGVR).Namespace(k.Namespace).Get(ctx, k.Name, metav1.GetOptions{ResourceVersion: revision})
	if err != nil {
		return nil, K8sErrorToCalico(err, key)
	}
	if !vmimShouldEmitLiveMigration(u) {
		return nil, cerrors.ErrorResourceDoesNotExist{Identifier: key}
	}
	return convertVMIMToLiveMigration(u)
}

func (c *LiveMigrationClient) List(ctx context.Context, list model.ListInterface, revision string) (*model.KVPairList, error) {
	logContext := log.WithField("Resource", "LiveMigration")
	logContext.Debug("Received List request")
	l := list.(model.ResourceListOptions)

	opts := metav1.ListOptions{ResourceVersion: revision}
	if revision != "" {
		opts.ResourceVersionMatch = metav1.ResourceVersionMatchNotOlderThan
	}

	result, err := c.dynClient.Resource(vmimGVR).Namespace(l.Namespace).List(ctx, opts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}

	kvps := []*model.KVPair{}
	for i := range result.Items {
		if !vmimShouldEmitLiveMigration(&result.Items[i]) {
			continue
		}
		kvp, err := convertVMIMToLiveMigration(&result.Items[i])
		if err != nil {
			logContext.WithError(err).WithField("name", result.Items[i].GetName()).Warning("unable to process VMIM resource, skipping")
			continue
		}
		kvps = append(kvps, kvp)
	}

	return &model.KVPairList{
		KVPairs:  kvps,
		Revision: result.GetResourceVersion(),
	}, nil
}

func (c *LiveMigrationClient) Watch(ctx context.Context, list model.ListInterface, options api.WatchOptions) (api.WatchInterface, error) {
	rlo := list.(model.ResourceListOptions)
	k8sOpts := watchOptionsToK8sListOptions(options)
	k8sWatch, err := c.dynClient.Resource(vmimGVR).Namespace(rlo.Namespace).Watch(ctx, k8sOpts)
	if err != nil {
		return nil, K8sErrorToCalico(err, list)
	}
	adapted := newVMIMWatchAdapter(k8sWatch)
	return newK8sWatcherConverter(ctx, "VirtualMachineInstanceMigration", convertVMIMResourceToLiveMigration, adapted), nil
}

func (c *LiveMigrationClient) EnsureInitialized() error {
	return nil
}

// vmimShouldEmitLiveMigration returns true if the VMIM is in a phase that
// warrants emitting a LiveMigration resource and has the required fields set.
func vmimShouldEmitLiveMigration(u *unstructured.Unstructured) bool {
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
	switch phase {
	case "TargetReady", "Running", "Failed":
	default:
		return false
	}
	vmiName, _, _ := unstructured.NestedString(u.Object, "spec", "vmiName")
	if vmiName == "" {
		return false
	}
	sourcePod, _, _ := unstructured.NestedString(u.Object, "status", "migrationState", "sourcePod")
	if sourcePod == "" {
		return false
	}
	if string(u.GetUID()) == "" {
		return false
	}
	return true
}

// convertVMIMToLiveMigrationSpec extracts the LiveMigrationSpec from a VMIM.
// The caller must ensure the VMIM has the required fields (see vmimShouldEmitLiveMigration).
func convertVMIMToLiveMigrationSpec(u *unstructured.Unstructured) libapiv3.LiveMigrationSpec {
	vmiName, _, _ := unstructured.NestedString(u.Object, "spec", "vmiName")
	migrationUID := string(u.GetUID())
	sourcePod, _, _ := unstructured.NestedString(u.Object, "status", "migrationState", "sourcePod")
	return libapiv3.LiveMigrationSpec{
		DestinationWorkloadEndpointSelector: fmt.Sprintf(
			"kubevirt.io/vmi-name == '%s' && kubevirt.io/migrationJobUID == '%s'",
			vmiName, migrationUID,
		),
		SourceWorkloadEndpoint: types.NamespacedName{
			Name:      sourcePod,
			Namespace: u.GetNamespace(),
		},
	}
}

// convertVMIMToLiveMigration converts a KubeVirt VirtualMachineInstanceMigration
// (represented as an *unstructured.Unstructured) to a Calico LiveMigration KVPair.
func convertVMIMToLiveMigration(u *unstructured.Unstructured) (*model.KVPair, error) {
	lm := libapiv3.NewLiveMigration()
	lm.Name = u.GetName()
	lm.Namespace = u.GetNamespace()
	lm.ResourceVersion = u.GetResourceVersion()
	lm.CreationTimestamp = u.GetCreationTimestamp()
	lm.UID = u.GetUID()
	lm.Labels = u.GetLabels()
	lm.Annotations = u.GetAnnotations()
	lm.Spec = convertVMIMToLiveMigrationSpec(u)
	return &model.KVPair{
		Key: model.ResourceKey{
			Kind:      libapiv3.KindLiveMigration,
			Namespace: u.GetNamespace(),
			Name:      u.GetName(),
		},
		Value:    lm,
		Revision: u.GetResourceVersion(),
	}, nil
}

// convertVMIMResourceToLiveMigration is a ConvertK8sResourceToKVPair adapter
// that unwraps the unstructuredResource wrapper used by the watch adapter.
func convertVMIMResourceToLiveMigration(r Resource) (*model.KVPair, error) {
	return convertVMIMToLiveMigration(r.(*unstructuredResource).Unstructured)
}

// unstructuredResource wraps *unstructured.Unstructured to implement the
// Resource interface (adding ObjectMetaAccessor).
type unstructuredResource struct {
	*unstructured.Unstructured
}

func (u *unstructuredResource) GetObjectMeta() metav1.Object {
	return u.Unstructured
}

// vmimWatchAdapter wraps a kwatch.Interface from the dynamic client and
// performs phase filtering and spec-change deduplication for VMIM→LiveMigration
// conversion. It tracks the last-emitted spec for each active VMIM and
// synthesises Added/Deleted events on phase transitions.
type vmimWatchAdapter struct {
	inner  kwatch.Interface
	ch     chan kwatch.Event
	active map[string]libapiv3.LiveMigrationSpec
}

func newVMIMWatchAdapter(inner kwatch.Interface) kwatch.Interface {
	w := &vmimWatchAdapter{
		inner:  inner,
		ch:     make(chan kwatch.Event, resultsBufSize),
		active: make(map[string]libapiv3.LiveMigrationSpec),
	}
	go w.run()
	return w
}

func (w *vmimWatchAdapter) Stop() {
	w.inner.Stop()
}

func (w *vmimWatchAdapter) ResultChan() <-chan kwatch.Event {
	return w.ch
}

func (w *vmimWatchAdapter) run() {
	defer close(w.ch)
	for event := range w.inner.ResultChan() {
		u, ok := event.Object.(*unstructured.Unstructured)
		if !ok {
			// Pass through Bookmark/Error events unchanged.
			w.ch <- event
			continue
		}
		key := u.GetNamespace() + "/" + u.GetName()
		wrapped := &unstructuredResource{Unstructured: u}

		switch event.Type {
		case kwatch.Added, kwatch.Modified:
			matches := vmimShouldEmitLiveMigration(u)
			_, wasActive := w.active[key]

			if matches {
				spec := convertVMIMToLiveMigrationSpec(u)
				if !wasActive {
					w.active[key] = spec
					w.ch <- kwatch.Event{Type: kwatch.Added, Object: wrapped}
				} else if !reflect.DeepEqual(spec, w.active[key]) {
					w.active[key] = spec
					w.ch <- kwatch.Event{Type: kwatch.Modified, Object: wrapped}
				}
				// else: unchanged spec → no-op
			} else if wasActive {
				delete(w.active, key)
				w.ch <- kwatch.Event{Type: kwatch.Deleted, Object: wrapped}
			}
			// else: does not match and was not active → no-op

		case kwatch.Deleted:
			if _, wasActive := w.active[key]; wasActive {
				delete(w.active, key)
				w.ch <- kwatch.Event{Type: kwatch.Deleted, Object: wrapped}
			}
			// else: was not active → no-op

		default:
			w.ch <- kwatch.Event{Type: event.Type, Object: wrapped}
		}
	}
}
