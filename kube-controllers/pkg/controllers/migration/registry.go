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

	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
)

const (
	// migratedByAnnotation is set on v3 resources created during migration so
	// the abort path can distinguish them from pre-existing v3 resources.
	migratedByAnnotation = "migration.projectcalico.org/migrated-by"

	// defaultWorkerCount is the number of concurrent workers for creating v3
	// resources within a single resource type.
	defaultWorkerCount = 10
)

// ConflictInfo identifies a resource that exists in v3 with a different spec than v1.
type ConflictInfo struct {
	Kind string
	Name string
}

func (c ConflictInfo) String() string {
	return fmt.Sprintf("%s/%s: v3 resource exists with different spec", c.Kind, c.Name)
}

// MigrationResult tracks the result of migrating a single resource type.
type MigrationResult struct {
	Migrated  int
	Skipped   int
	Conflicts []ConflictInfo

	// UIDMapping records v1 UID → v3 UID for resources that were created or
	// already existed. Used by RemapOwnerReferences after all types are migrated.
	UIDMapping map[types.UID]types.UID

	// ObjectsWithCalicoOwnerRefs holds v3 objects that have OwnerReferences
	// pointing to Calico API groups. Collected during migration so the
	// remapping pass doesn't need to re-list from the API server.
	ObjectsWithCalicoOwnerRefs []client.Object
}

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
	v3Obj  client.Object
	logCtx *logrus.Entry
}

// migrationWorkResult holds the outcome of processing a single work item.
type migrationWorkResult struct {
	migrated bool
	skipped  bool
	conflict *ConflictInfo
	v1UID    types.UID
	v3UID    types.UID
	err      error

	// v3Obj is set when the migrated/skipped object has Calico OwnerRefs
	// that may need UID remapping.
	v3Obj client.Object
}

// MigrateResourceType runs the migration for a single resource type using the
// given migrator. It lists and converts resources sequentially, then fans out
// create/check operations to a bounded worker pool for concurrency.
func MigrateResourceType(ctx context.Context, m migrators.ResourceMigrator) (*MigrationResult, error) {
	logCtx := logrus.WithField("kind", m.Kind())
	logCtx.Info("Starting migration for resource type")

	result := &MigrationResult{
		UIDMapping: make(map[types.UID]types.UID),
	}

	// Phase 1: List all v1 resources (already converted to v3 objects).
	v1Objects, err := m.ListV1(ctx)
	if err != nil {
		return nil, fmt.Errorf("listing v1 %s resources: %w", m.Kind(), err)
	}
	logCtx.WithField("count", len(v1Objects)).Info("Listed v1 resources")

	workItems := make([]migrationWorkItem, 0, len(v1Objects))
	for _, obj := range v1Objects {
		// The converted object retains the v1 UID for mapping purposes.
		v1UID := obj.GetUID()

		// Clear UID before creation — the API server assigns a new one.
		obj.SetUID("")

		entryLog := logCtx.WithFields(logrus.Fields{
			"v1UID":     v1UID,
			"ownerRefs": len(obj.GetOwnerReferences()),
			"name":      obj.GetName(),
			"namespace": obj.GetNamespace(),
		})

		workItems = append(workItems, migrationWorkItem{
			v1UID:  v1UID,
			v3Obj:  obj,
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
		if r.conflict != nil {
			result.Conflicts = append(result.Conflicts, *r.conflict)
		}
		if r.v1UID != "" && r.v3UID != "" {
			result.UIDMapping[r.v1UID] = r.v3UID
		}
		if r.v3Obj != nil {
			result.ObjectsWithCalicoOwnerRefs = append(result.ObjectsWithCalicoOwnerRefs, r.v3Obj)
		}
	}

	logCtx.WithFields(logrus.Fields{
		"migrated":  result.Migrated,
		"skipped":   result.Skipped,
		"conflicts": len(result.Conflicts),
	}).Info("Completed migration for resource type")

	return result, nil
}

// DetectConflicts checks all migrators for v1 resources that have a corresponding
// v3 resource with a different spec. It returns a ConflictInfo for each mismatch.
func DetectConflicts(ctx context.Context, ms []migrators.ResourceMigrator) ([]ConflictInfo, error) {
	var allConflicts []ConflictInfo
	for _, m := range ms {
		v1Objects, err := m.ListV1(ctx)
		if err != nil {
			return nil, fmt.Errorf("listing v1 %s: %w", m.Kind(), err)
		}
		for _, obj := range v1Objects {
			existing, err := m.GetV3(ctx, obj.GetName(), obj.GetNamespace())
			if err != nil || existing == nil {
				continue
			}
			if !m.SpecsEqual(obj, existing) {
				allConflicts = append(allConflicts, ConflictInfo{Kind: m.Kind(), Name: obj.GetName()})
			}
		}
	}
	return allConflicts, nil
}

// migrateOneResource handles the create/check/conflict logic for a single
// resource. It is called concurrently from the worker pool. Transient API
// errors are retried with exponential backoff.
func migrateOneResource(ctx context.Context, m migrators.ResourceMigrator, item migrationWorkItem) migrationWorkResult {
	v3Obj := item.v3Obj

	// Check if a v3 resource already exists (with retry).
	var existing client.Object
	err := wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		var getErr error
		existing, getErr = m.GetV3(ctx, v3Obj.GetName(), v3Obj.GetNamespace())
		if getErr != nil && isRetryable(getErr) {
			migrationRetries.WithLabelValues(m.Kind(), "get").Inc()
			item.logCtx.WithError(getErr).Debug("Retrying GetV3")
			return false, nil
		}
		return true, getErr
	})
	if err != nil {
		return migrationWorkResult{
			err: fmt.Errorf("checking existing v3 %s/%s: %w", m.Kind(), v3Obj.GetName(), err),
		}
	}

	if existing != nil {
		if m.SpecsEqual(v3Obj, existing) {
			item.logCtx.Debug("v3 resource already exists with matching spec, skipping")
			r := migrationWorkResult{skipped: true, v1UID: item.v1UID, v3UID: existing.GetUID()}
			if hasCalicoOwnerRefs(existing) {
				r.v3Obj = existing
			}
			return r
		}
		ci := &ConflictInfo{Kind: m.Kind(), Name: v3Obj.GetName()}
		item.logCtx.Warn(ci.String())
		return migrationWorkResult{conflict: ci}
	}

	// Stamp the migration annotation so the abort path can distinguish
	// resources created by migration from pre-existing v3 resources.
	annotations := v3Obj.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations[migratedByAnnotation] = "v1-to-v3"
	v3Obj.SetAnnotations(annotations)

	// Create the v3 resource (with retry). CreateV3 populates the object
	// in-place with the server response (including UID), so no read-back
	// is needed.
	err = wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		createErr := m.CreateV3(ctx, v3Obj)
		if createErr != nil {
			if kerrors.IsAlreadyExists(createErr) {
				return true, createErr
			}
			if isRetryable(createErr) {
				migrationRetries.WithLabelValues(m.Kind(), "create").Inc()
				item.logCtx.WithError(createErr).Debug("Retrying CreateV3")
				return false, nil
			}
			return true, createErr
		}
		return true, nil
	})
	if err != nil {
		if kerrors.IsAlreadyExists(err) {
			item.logCtx.Debug("v3 resource was created concurrently, reading back for UID mapping")
			readBack, getErr := m.GetV3(ctx, v3Obj.GetName(), v3Obj.GetNamespace())
			if getErr != nil {
				return migrationWorkResult{err: fmt.Errorf("reading back AlreadyExists v3 %s/%s: %w", m.Kind(), v3Obj.GetName(), getErr)}
			}
			r := migrationWorkResult{skipped: true, v1UID: item.v1UID}
			if readBack != nil {
				r.v3UID = readBack.GetUID()
				if hasCalicoOwnerRefs(readBack) {
					r.v3Obj = readBack
				}
			}
			return r
		}
		return migrationWorkResult{
			err: fmt.Errorf("creating v3 %s/%s: %w", m.Kind(), v3Obj.GetName(), err),
		}
	}
	item.logCtx.Debug("Successfully migrated resource")

	r := migrationWorkResult{migrated: true, v1UID: item.v1UID, v3UID: v3Obj.GetUID()}
	if hasCalicoOwnerRefs(v3Obj) {
		r.v3Obj = v3Obj
	}
	return r
}

// hasCalicoOwnerRefs returns true if the object has any OwnerReferences
// pointing to a Calico API group.
func hasCalicoOwnerRefs(obj client.Object) bool {
	for _, ref := range obj.GetOwnerReferences() {
		if isCalicoAPIGroup(ref.APIVersion) {
			return true
		}
	}
	return false
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

// RemapOwnerReferences remaps Calico OwnerReference UIDs on the given objects
// using the v1→v3 UID map. The objects are ones collected during the migration
// pass that have Calico OwnerRefs, so no API server listing is needed.
func RemapOwnerReferences(
	ctx context.Context,
	uidMap map[types.UID]types.UID,
	objects []client.Object,
	update func(ctx context.Context, obj client.Object, opts ...client.UpdateOption) error,
) error {
	if len(uidMap) == 0 || len(objects) == 0 {
		return nil
	}

	logCtx := logrus.WithFields(logrus.Fields{
		"uidMappings": len(uidMap),
		"candidates":  len(objects),
	})
	logCtx.Info("Remapping OwnerReference UIDs on migrated resources")

	remapped := 0
	for _, obj := range objects {
		ownerRefs := obj.GetOwnerReferences()
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
			if err := update(ctx, obj); err != nil {
				return fmt.Errorf("updating ownerrefs on %s/%s: %w", obj.GetObjectKind().GroupVersionKind().Kind, obj.GetName(), err)
			}
			remapped++
		}
	}

	logCtx.WithField("remapped", remapped).Info("Completed OwnerReference remapping")
	return nil
}
