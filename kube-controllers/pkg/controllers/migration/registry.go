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
	"reflect"
	"strings"
	"sync"
	"time"

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/projectcalico/calico/libcalico-go/lib/backend/api"
	"github.com/projectcalico/calico/libcalico-go/lib/backend/model"
)

const (
	// migratedByAnnotation is set on v3 resources created during migration so
	// the abort path can distinguish them from pre-existing v3 resources.
	migratedByAnnotation = "migration.projectcalico.org/migrated-by"

	// defaultWorkerCount is the number of concurrent workers for creating v3
	// resources within a single resource type.
	defaultWorkerCount = 10
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
	Convert func(kvp *model.KVPair) (client.Object, error)

	// V3Object returns a new empty instance of the v3 type (e.g., &apiv3.Tier{}).
	V3Object func() client.Object

	// V3ObjectList returns a new empty list instance (e.g., &apiv3.TierList{}).
	V3ObjectList func() client.ObjectList

	// GetSpec extracts the Spec field from a typed v3 object for comparison.
	GetSpec func(obj client.Object) any
}

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
}

// registry holds all registered resource migrators, ordered by migration priority.
var (
	registryMu sync.Mutex
	registry   []ResourceMigrator
)

// Register adds a ResourceMigrator to the global registry.
func Register(m ResourceMigrator) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = append(registry, m)
}

// GetRegistry returns a copy of all registered migrators.
func GetRegistry() []ResourceMigrator {
	registryMu.Lock()
	defer registryMu.Unlock()
	result := make([]ResourceMigrator, len(registry))
	copy(result, registry)
	return result
}

// migratedPolicyName handles the default. prefix removal for default-tier policies.
func migratedPolicyName(name, tier string) string {
	if (tier == "default" || tier == "") && strings.HasPrefix(name, "default.") {
		return strings.TrimPrefix(name, "default.")
	}
	return name
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
}

// MigrateResourceType runs the migration for a single resource type using the
// given migrator. It lists and converts resources sequentially, then fans out
// create/check operations to a bounded worker pool for concurrency.
func MigrateResourceType(ctx context.Context, bc api.Client, rtClient client.Client, m ResourceMigrator) (*MigrationResult, error) {
	logCtx := logrus.WithField("kind", m.Kind)
	logCtx.Info("Starting migration for resource type")

	result := &MigrationResult{
		UIDMapping: make(map[types.UID]types.UID),
	}

	// Phase 1: List all v1 resources and convert to v3 objects sequentially.
	v1List, err := m.ListV1(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("listing v1 %s resources: %w", m.Kind, err)
	}
	logCtx.WithField("count", len(v1List.KVPairs)).Info("Listed v1 resources")

	workItems := make([]migrationWorkItem, 0, len(v1List.KVPairs))
	for _, kvp := range v1List.KVPairs {
		key, ok := kvp.Key.(model.ResourceKey)
		if !ok {
			return nil, fmt.Errorf("unexpected key type for %s: %T", m.Kind, kvp.Key)
		}
		v1Src, ok := kvp.Value.(metav1.Object)
		if !ok {
			return nil, fmt.Errorf("unexpected value type for %s/%s: %T", m.Kind, key.Name, kvp.Value)
		}
		v1UID := v1Src.GetUID()

		v3Obj, err := m.Convert(kvp)
		if err != nil {
			return nil, fmt.Errorf("converting %s/%s: %w", m.Kind, key.Name, err)
		}

		// Copy OwnerReferences from the v1 source. UIDs referencing Calico
		// resources will be stale at this point — they get remapped in a
		// second pass after all types are migrated.
		if ownerRefs := v1Src.GetOwnerReferences(); len(ownerRefs) > 0 {
			v3Obj.SetOwnerReferences(ownerRefs)
		}

		entryLog := logCtx.WithFields(logrus.Fields{
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
				resultCh <- migrateOneResource(ctx, rtClient, m, item)
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
	}

	logCtx.WithFields(logrus.Fields{
		"migrated":  result.Migrated,
		"skipped":   result.Skipped,
		"conflicts": len(result.Conflicts),
	}).Info("Completed migration for resource type")

	return result, nil
}

// CheckConflicts lists all v1 resources for a given migrator and checks each
// one against the corresponding v3 resource. It returns a ConflictInfo for
// each resource where the v3 spec differs from the converted v1 spec.
func CheckConflicts(ctx context.Context, bc api.Client, rtClient client.Client, m ResourceMigrator) ([]ConflictInfo, error) {
	v1List, err := m.ListV1(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("listing v1 %s: %w", m.Kind, err)
	}

	var conflicts []ConflictInfo
	for _, kvp := range v1List.KVPairs {
		v1Obj, err := m.Convert(kvp)
		if err != nil {
			return nil, fmt.Errorf("converting v1 %s: %w", m.Kind, err)
		}

		existing := m.V3Object()
		getErr := rtClient.Get(ctx, types.NamespacedName{Name: v1Obj.GetName(), Namespace: v1Obj.GetNamespace()}, existing)
		if getErr != nil {
			if kerrors.IsNotFound(getErr) {
				continue
			}
			return nil, fmt.Errorf("getting v3 %s/%s: %w", m.Kind, v1Obj.GetName(), getErr)
		}
		if !reflect.DeepEqual(m.GetSpec(v1Obj), m.GetSpec(existing)) {
			conflicts = append(conflicts, ConflictInfo{Kind: m.Kind, Name: v1Obj.GetName()})
		}
	}
	return conflicts, nil
}

// getV3Object fetches a v3 resource by name/namespace using the controller-runtime client.
// Returns nil, nil if the resource does not exist.
func getV3Object(ctx context.Context, rtClient client.Client, m ResourceMigrator, name, namespace string) (client.Object, error) {
	obj := m.V3Object()
	err := rtClient.Get(ctx, types.NamespacedName{Name: name, Namespace: namespace}, obj)
	if err != nil {
		if kerrors.IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	return obj, nil
}

// migrateOneResource handles the create/check/conflict logic for a single
// resource. It is called concurrently from the worker pool. Transient API
// errors are retried with exponential backoff.
func migrateOneResource(ctx context.Context, rtClient client.Client, m ResourceMigrator, item migrationWorkItem) migrationWorkResult {
	v3Obj := item.v3Obj

	// Check if a v3 resource already exists (with retry).
	var existing client.Object
	err := wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		var getErr error
		existing, getErr = getV3Object(ctx, rtClient, m, v3Obj.GetName(), v3Obj.GetNamespace())
		if getErr != nil && isRetryable(getErr) {
			migrationRetries.WithLabelValues(m.Kind, "get").Inc()
			item.logCtx.WithError(getErr).Debug("Retrying GetV3")
			return false, nil
		}
		return true, getErr
	})
	if err != nil {
		return migrationWorkResult{
			err: fmt.Errorf("checking existing v3 %s/%s: %w", m.Kind, v3Obj.GetName(), err),
		}
	}

	if existing != nil {
		if reflect.DeepEqual(m.GetSpec(v3Obj), m.GetSpec(existing)) {
			item.logCtx.Debug("v3 resource already exists with matching spec, skipping")
			return migrationWorkResult{skipped: true, v1UID: item.v1UID, v3UID: existing.GetUID()}
		}
		ci := &ConflictInfo{Kind: m.Kind, Name: v3Obj.GetName()}
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

	// Create the v3 resource (with retry).
	err = wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		createErr := rtClient.Create(ctx, v3Obj)
		if createErr != nil {
			if kerrors.IsAlreadyExists(createErr) {
				return true, createErr
			}
			if isRetryable(createErr) {
				migrationRetries.WithLabelValues(m.Kind, "create").Inc()
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
			readBack, getErr := getV3Object(ctx, rtClient, m, v3Obj.GetName(), v3Obj.GetNamespace())
			if getErr != nil {
				return migrationWorkResult{err: fmt.Errorf("reading back AlreadyExists v3 %s/%s: %w", m.Kind, v3Obj.GetName(), getErr)}
			}
			var v3UID types.UID
			if readBack != nil {
				v3UID = readBack.GetUID()
			}
			return migrationWorkResult{skipped: true, v1UID: item.v1UID, v3UID: v3UID}
		}
		return migrationWorkResult{
			err: fmt.Errorf("creating v3 %s/%s: %w", m.Kind, v3Obj.GetName(), err),
		}
	}
	item.logCtx.Debug("Successfully migrated resource")

	// Read back the created resource to get the server-assigned UID (with retry).
	var created client.Object
	err = wait.ExponentialBackoffWithContext(ctx, retryBackoff, func(ctx context.Context) (bool, error) {
		var getErr error
		created, getErr = getV3Object(ctx, rtClient, m, v3Obj.GetName(), v3Obj.GetNamespace())
		if getErr != nil && isRetryable(getErr) {
			migrationRetries.WithLabelValues(m.Kind, "get").Inc()
			item.logCtx.WithError(getErr).Debug("Retrying read-back GetV3")
			return false, nil
		}
		return true, getErr
	})
	if err != nil {
		return migrationWorkResult{
			err: fmt.Errorf("reading back created v3 %s/%s: %w", m.Kind, v3Obj.GetName(), err),
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
func RemapOwnerReferences(ctx context.Context, rtClient client.Client, uidMap map[types.UID]types.UID, migrators []ResourceMigrator) error {
	if len(uidMap) == 0 {
		return nil
	}

	logCtx := logrus.WithField("uidMappings", len(uidMap))
	logCtx.Info("Remapping OwnerReference UIDs on migrated resources")

	remapped := 0
	for _, m := range migrators {
		if m.V3ObjectList == nil {
			continue
		}

		list := m.V3ObjectList()
		if err := rtClient.List(ctx, list); err != nil {
			return fmt.Errorf("listing v3 %s for ownerref remapping: %w", m.Kind, err)
		}

		// Extract items from the list using reflection.
		items := extractItems(list)
		for _, obj := range items {
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
				if err := rtClient.Update(ctx, obj); err != nil {
					return fmt.Errorf("updating ownerrefs on %s/%s: %w", m.Kind, obj.GetName(), err)
				}
				remapped++
			}
		}
	}

	logCtx.WithField("remapped", remapped).Info("Completed OwnerReference remapping")
	return nil
}

// extractItems uses reflection to pull the Items slice from a typed list object
// (e.g., apiv3.TierList) and return them as []client.Object.
func extractItems(list client.ObjectList) []client.Object {
	v := reflect.ValueOf(list)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	itemsField := v.FieldByName("Items")
	if !itemsField.IsValid() {
		return nil
	}
	result := make([]client.Object, itemsField.Len())
	for i := range itemsField.Len() {
		item := itemsField.Index(i).Addr().Interface()
		if obj, ok := item.(client.Object); ok {
			result[i] = obj
		}
	}
	return result
}

// copyLabelsAndAnnotations copies labels and annotations from a v1 resource (read via libcalico-go)
// to a new v3 object, filtering out internal metadata annotations.
func copyLabelsAndAnnotations(src, dst metav1.Object) {
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
