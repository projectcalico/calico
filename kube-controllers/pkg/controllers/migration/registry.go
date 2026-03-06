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

	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	log "github.com/sirupsen/logrus"
	kerrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

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
}

// MigrationResult tracks the result of migrating a single resource type.
type MigrationResult struct {
	Migrated  int
	Skipped   int
	Conflicts []string
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

// MigrateResourceType runs the migration for a single resource type using the given migrator.
func MigrateResourceType(ctx context.Context, bc api.Client, m ResourceMigrator) (*MigrationResult, error) {
	logCtx := log.WithField("kind", m.Kind)
	logCtx.Info("Starting migration for resource type")

	result := &MigrationResult{}

	v1List, err := m.ListV1(ctx, bc)
	if err != nil {
		return nil, fmt.Errorf("listing v1 %s resources: %v", m.Kind, err)
	}
	logCtx.WithField("count", len(v1List.KVPairs)).Info("Listed v1 resources")

	for _, kvp := range v1List.KVPairs {
		key := kvp.Key.(model.ResourceKey)
		entryLog := logCtx.WithFields(log.Fields{
			"name":      key.Name,
			"namespace": key.Namespace,
		})

		v3Obj, err := m.Convert(kvp)
		if err != nil {
			return nil, fmt.Errorf("converting %s/%s: %v", m.Kind, key.Name, err)
		}

		// Check if a v3 resource already exists.
		existing, err := m.GetV3(ctx, v3Obj.GetName(), v3Obj.GetNamespace())
		if err != nil {
			return nil, fmt.Errorf("checking existing v3 %s/%s: %v", m.Kind, v3Obj.GetName(), err)
		}

		if existing != nil {
			if m.SpecsEqual(v3Obj, existing) {
				entryLog.Debug("v3 resource already exists with matching spec, skipping")
				result.Skipped++
				continue
			}
			conflict := fmt.Sprintf("%s/%s: v3 resource exists with different spec", m.Kind, v3Obj.GetName())
			entryLog.Warn(conflict)
			result.Conflicts = append(result.Conflicts, conflict)
			continue
		}

		// Create the v3 resource.
		err = m.CreateV3(ctx, v3Obj)
		if err != nil {
			if kerrors.IsAlreadyExists(err) {
				entryLog.Debug("v3 resource was created concurrently, skipping")
				result.Skipped++
				continue
			}
			return nil, fmt.Errorf("creating v3 %s/%s: %v", m.Kind, v3Obj.GetName(), err)
		}
		entryLog.Debug("Successfully migrated resource")
		result.Migrated++
	}

	logCtx.WithFields(log.Fields{
		"migrated":  result.Migrated,
		"skipped":   result.Skipped,
		"conflicts": len(result.Conflicts),
	}).Info("Completed migration for resource type")

	return result, nil
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
