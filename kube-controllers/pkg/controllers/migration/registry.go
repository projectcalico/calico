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

package migration

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

// ResourceMigrator defines how to migrate a single resource type from v1 to v3 CRDs.
type ResourceMigrator struct {
	// Kind is the Calico resource kind (e.g., "GlobalNetworkPolicy").
	Kind string

	// Namespaced indicates whether this resource type is namespaced.
	Namespaced bool

	// Order controls migration ordering. Lower numbers are migrated first.
	Order int

	// ListV1 lists all v1 resources of this type using the libcalico-go backend client.
	ListV1 func(ctx context.Context, client api.Client) (*model.KVPairList, error)

	// Convert transforms a v1 KVPair into a v3 object suitable for creation.
	// The returned object should have Name, Namespace, Labels, Annotations, and Spec set.
	// It should NOT have ResourceVersion, UID, or CreationTimestamp set.
	Convert func(kvp *model.KVPair) (metav1.Object, error)

	// CreateV3 creates the v3 resource via the typed clientset.
	CreateV3 func(ctx context.Context, obj metav1.Object) error

	// GetV3 attempts to get an existing v3 resource by name/namespace.
	// Returns nil, nil if the resource does not exist.
	GetV3 func(ctx context.Context, name, namespace string) (metav1.Object, error)

	// SpecsEqual compares the spec of two objects to determine if they are equivalent.
	SpecsEqual func(v1Obj, v3Obj metav1.Object) bool

	// ListV3 lists all v3 resources of this type. Used for OwnerReference remapping.
	ListV3 func(ctx context.Context) ([]metav1.Object, error)

	// UpdateV3 updates a v3 resource (used for OwnerReference remapping).
	UpdateV3 func(ctx context.Context, obj metav1.Object) error

	// DeleteV3 deletes a v3 resource by name and namespace.
	DeleteV3 func(ctx context.Context, name, namespace string) error
}

// MigrationResult tracks the result of migrating a single resource type.
type MigrationResult struct {
	Migrated  int
	Skipped   int
	Conflicts []string

	// UIDMapping records v1 UID → v3 UID for resources that were created or
	// already existed. Used by RemapOwnerReferences after all types are migrated.
	UIDMapping map[types.UID]types.UID
}

// registry holds all registered resource migrators, ordered by migration priority.
var registry []ResourceMigrator

// Register adds a ResourceMigrator to the global registry.
func Register(m ResourceMigrator) {
	registry = append(registry, m)
}

// GetRegistry returns all registered migrators, sorted by Order.
func GetRegistry() []ResourceMigrator {
	// Registry is already built in order via init() calls.
	return registry
}

// migratedPolicyName handles the default. prefix removal for default-tier policies.
func migratedPolicyName(name, tier string) string {
	if (tier == "default" || tier == "") && strings.HasPrefix(name, "default.") {
		return strings.TrimPrefix(name, "default.")
	}
	return name
}

// defaultWorkerCount is the number of concurrent workers for creating v3
// resources within a single resource type. The design doc suggests 10 as a
// conservative default; on clusters with a healthy API server, higher values
// (20-50) would be safe.
const defaultWorkerCount = 10

// retryBackoff defines the backoff parameters for retrying transient API errors
// during resource migration (e.g., server timeouts, throttling, connection resets).
var retryBackoff = wait.Backoff{
	Duration: 200 * time.Millisecond,
	Factor:   2.0,
	Jitter:   0.1,
	Steps:    5,
	Cap:      10 * time.Second,
}

// isRetryable returns true for errors that are likely transient and worth retrying.
func isRetryable(err error) bool {
	return kerrors.IsServerTimeout(err) ||
		kerrors.IsTimeout(err) ||
		kerrors.IsTooManyRequests(err) ||
		kerrors.IsServiceUnavailable(err) ||
		kerrors.IsInternalError(err)
}

// migrationWorkItem holds a pre-converted v3 object ready for the worker pool
// to create or conflict-check.
type migrationWorkItem struct {
	v1UID  types.UID
	v3Obj  metav1.Object
	logCtx *log.Entry
}

// migrationWorkResult holds the outcome of processing a single work item.
type migrationWorkResult struct {
	migrated bool
	skipped  bool
	conflict string
	v1UID    types.UID
	v3UID    types.UID
	err      error
}

// MigrateResourceType runs the migration for a single resource type using the
// given migrator. It lists and converts resources sequentially, then fans out
// create/check operations to a bounded worker pool for concurrency.
func MigrateResourceType(ctx context.Context, bc api.Client, m ResourceMigrator) (*MigrationResult, error) {
	logCtx := log.WithField("kind", m.Kind)
	logCtx.Info("Starting migration for resource type")

	result := &MigrationResult{
		UIDMapping: make(map[types.UID]types.UID),
	}

	// Phase 1: List all v1 resources and convert to v3 objects sequentially.
	v1List, err := m.ListV1(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("listing v1 %s resources: %v", m.Kind, err)
	}
	logCtx.WithField("count", len(v1List.KVPairs)).Info("Listed v1 resources")

	workItems := make([]migrationWorkItem, 0, len(v1List.KVPairs))
	for _, kvp := range v1List.KVPairs {
		key := kvp.Key.(model.ResourceKey)
		v1Src := kvp.Value.(metav1.Object)
		v1UID := v1Src.GetUID()

		v3Obj, err := m.Convert(kvp)
		if err != nil {
			return nil, fmt.Errorf("converting %s/%s: %v", m.Kind, key.Name, err)
		}

		// Copy OwnerReferences from the v1 source. UIDs referencing Calico
		// resources will be stale at this point — they get remapped in a
		// second pass after all types are migrated.
		if ownerRefs := v1Src.GetOwnerReferences(); len(ownerRefs) > 0 {
			v3Obj.SetOwnerReferences(ownerRefs)
		}

		entryLog := logCtx.WithFields(log.Fields{
			"v1UID":     v1UID,
			"ownerRefs": len(v1Src.GetOwnerReferences()),
			"name":      key.Name,
			"namespace": key.Namespace,
		})

		workItems = append(workItems, migrationWorkItem{
			v1UID:  v1UID,
			v3Obj:  v3Obj,
			logCtx: entryLog,
		})
	}

	// Phase 2: Fan out create/check operations to a bounded worker pool.
	workers := defaultWorkerCount
	if len(workItems) < workers {
		workers = len(workItems)
	}
	if workers == 0 {
		logCtx.Info("No resources to migrate")
		return result, nil
	}

	workCh := make(chan migrationWorkItem, len(workItems))
	for _, item := range workItems {
		workCh <- item
	}
	close(workCh)

	resultCh := make(chan migrationWorkResult, len(workItems))
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for item := range workCh {
				resultCh <- migrateOneResource(ctx, m, item)
			}
		}()
	}
	wg.Wait()
	close(resultCh)

	// Phase 3: Aggregate results.
	for r := range resultCh {
		if r.err != nil {
			return nil, r.err
		}
		if r.migrated {
			result.Migrated++
		}
		if r.skipped {
			result.Skipped++
		}
		if r.conflict != "" {
			result.Conflicts = append(result.Conflicts, r.conflict)
		}
		if r.v1UID != "" && r.v3UID != "" {
			result.UIDMapping[r.v1UID] = r.v3UID
		}
	}

	logCtx.WithFields(log.Fields{
		"migrated":  result.Migrated,
		"skipped":   result.Skipped,
		"conflicts": len(result.Conflicts),
	}).Info("Completed migration for resource type")

	return result, nil
}

// migrateOneResource handles the create/check/conflict logic for a single
// resource. It is called concurrently from the worker pool. Transient API
// errors are retried with exponential backoff.
func migrateOneResource(ctx context.Context, m ResourceMigrator, item migrationWorkItem) migrationWorkResult {
	v3Obj := item.v3Obj

	// Check if a v3 resource already exists (with retry).
	var existing metav1.Object
	err := wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		var getErr error
		existing, getErr = m.GetV3(ctx, v3Obj.GetName(), v3Obj.GetNamespace())
		if getErr != nil && isRetryable(getErr) {
			item.logCtx.WithError(getErr).Debug("Retrying GetV3")
			return false, nil
		}
		return true, getErr
	})
	if err != nil {
		return migrationWorkResult{
			err: fmt.Errorf("checking existing v3 %s/%s: %v", m.Kind, v3Obj.GetName(), err),
		}
	}

	if existing != nil {
		if m.SpecsEqual(v3Obj, existing) {
			item.logCtx.Debug("v3 resource already exists with matching spec, skipping")
			return migrationWorkResult{skipped: true, v1UID: item.v1UID, v3UID: existing.GetUID()}
		}
		conflict := fmt.Sprintf("%s/%s: v3 resource exists with different spec", m.Kind, v3Obj.GetName())
		item.logCtx.Warn(conflict)
		return migrationWorkResult{conflict: conflict}
	}

	// Create the v3 resource (with retry).
	err = wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		createErr := m.CreateV3(ctx, v3Obj)
		if createErr != nil {
			if kerrors.IsAlreadyExists(createErr) {
				return true, createErr
			}
			if isRetryable(createErr) {
				item.logCtx.WithError(createErr).Debug("Retrying CreateV3")
				return false, nil
			}
			return true, createErr
		}
		return true, nil
	})
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			item.logCtx.Debug("v3 resource was created concurrently, skipping")
			return migrationWorkResult{skipped: true}
		}
		return migrationWorkResult{
			err: fmt.Errorf("creating v3 %s/%s: %v", m.Kind, v3Obj.GetName(), err),
		}
	}
	item.logCtx.Debug("Successfully migrated resource")

	// Read back the created resource to get the server-assigned UID (with retry).
	var created metav1.Object
	err = wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		var getErr error
		created, getErr = m.GetV3(ctx, v3Obj.GetName(), v3Obj.GetNamespace())
		if getErr != nil && isRetryable(getErr) {
			item.logCtx.WithError(getErr).Debug("Retrying read-back GetV3")
			return false, nil
		}
		return true, getErr
	})
	if err != nil {
		return migrationWorkResult{
			err: fmt.Errorf("reading back created v3 %s/%s: %v", m.Kind, v3Obj.GetName(), err),
		}
	}
	var v3UID types.UID
	if created != nil {
		v3UID = created.GetUID()
	}
	return migrationWorkResult{migrated: true, v1UID: item.v1UID, v3UID: v3UID}
}

// isCalicoAPIGroup returns true if the given API group is a Calico group
// whose resources are being migrated (and thus whose UIDs may change).
func isCalicoAPIGroup(group string) bool {
	switch group {
	case "projectcalico.org", "crd.projectcalico.org":
		return true
	}
	// Also match versioned forms like "projectcalico.org/v3".
	return strings.HasPrefix(group, "projectcalico.org/") || strings.HasPrefix(group, "crd.projectcalico.org/")
}

// RemapOwnerReferences performs a second pass over all migrated v3 resources,
// remapping OwnerReference UIDs that point to Calico resources. Non-Calico
// OwnerReferences (e.g., to Namespaces or Pods) are left unchanged.
func RemapOwnerReferences(ctx context.Context, uidMap map[types.UID]types.UID, migrators []ResourceMigrator) error {
	if len(uidMap) == 0 {
		return nil
	}

	logCtx := log.WithField("uidMappings", len(uidMap))
	logCtx.Info("Remapping OwnerReference UIDs on migrated resources")

	remapped := 0
	for _, m := range migrators {
		if m.UpdateV3 == nil {
			continue
		}

		if m.ListV3 == nil {
			continue
		}

		v3List, err := m.ListV3(ctx)
		if err != nil {
			return fmt.Errorf("listing v3 %s for ownerref remapping: %v", m.Kind, err)
		}

		for _, obj := range v3List {
			ownerRefs := obj.GetOwnerReferences()
			if len(ownerRefs) == 0 {
				continue
			}

			changed := false
			for i, ref := range ownerRefs {
				if !isCalicoAPIGroup(ref.APIVersion) {
					continue
				}
				if newUID, ok := uidMap[ref.UID]; ok && newUID != ref.UID {
					ownerRefs[i].UID = newUID
					changed = true
				}
			}

			if changed {
				obj.SetOwnerReferences(ownerRefs)
				if err := m.UpdateV3(ctx, obj); err != nil {
					return fmt.Errorf("updating ownerrefs on %s/%s: %v", m.Kind, obj.GetName(), err)
				}
				remapped++
			}
		}
	}

	logCtx.WithField("remapped", remapped).Info("Completed OwnerReference remapping")
	return nil
}

// copyLabelsAndAnnotations copies labels and annotations from a v1 resource (read via libcalico-go)
// to a new v3 object, filtering out internal metadata annotations.
func copyLabelsAndAnnotations(src metav1.Object, dst metav1.Object) {
	if labels := src.GetLabels(); len(labels) > 0 {
		cleaned := make(map[string]string, len(labels))
		for k, v := range labels {
			cleaned[k] = v
		}
		dst.SetLabels(cleaned)
	}

	if annotations := src.GetAnnotations(); len(annotations) > 0 {
		cleaned := make(map[string]string)
		for k, v := range annotations {
			// Skip the internal metadata annotation used by the v1 backend.
			if k == "projectcalico.org/metadata" {
				continue
			}
			cleaned[k] = v
		}
		if len(cleaned) > 0 {
			dst.SetAnnotations(cleaned)
		}
	}
}

// listV1Resources is a helper to list v1 resources via the libcalico-go backend client.
func listV1Resources(ctx context.Context, bc api.Client, kind string) (*model.KVPairList, error) {
	return bc.List(ctx, model.ResourceListOptions{Kind: kind}, "")
}

// listV1NamespacedResources lists v1 resources across all namespaces.
func listV1NamespacedResources(ctx context.Context, bc api.Client, kind string) (*model.KVPairList, error) {
	return bc.List(ctx, model.ResourceListOptions{Kind: kind, Namespace: ""}, "")
}

// newV3TypeMeta returns a TypeMeta for the given kind.
func newV3TypeMeta(kind string) metav1.TypeMeta {
	return metav1.TypeMeta{
		APIVersion: apiv3.GroupVersionCurrent,
		Kind:       kind,
	}
}
