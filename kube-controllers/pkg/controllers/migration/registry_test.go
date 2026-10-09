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
	"testing"

	. "github.com/onsi/gomega"
	apiv3 "github.com/projectcalico/api/pkg/apis/projectcalico/v3"
	"k8s.io/apimachinery/pkg/types"
	ctrlfake "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/projectcalico/calico/kube-controllers/pkg/controllers/migration/migrators"
)

// TestMigrateResourceTypeStampsMigrationID verifies that created v3 resources
// record the ID of the migration that created them.
func TestMigrateResourceTypeStampsMigrationID(t *testing.T) {
	g := NewWithT(t)
	ctx := context.Background()

	rt := ctrlfake.NewClientBuilder().WithScheme(testScheme(t)).Build()
	bc := &mockBackendClient{resources: mainlineV1Resources()}

	result, err := MigrateResourceType(ctx, migratorForKind(t, NewMigrators(bc, rt), apiv3.KindTier), "migration-a")
	g.Expect(err).NotTo(HaveOccurred())
	g.Expect(result.Migrated).To(Equal(2))

	tier := &apiv3.Tier{}
	g.Expect(rt.Get(ctx, types.NamespacedName{Name: "security"}, tier)).To(Succeed())
	g.Expect(tier.Annotations).To(HaveKeyWithValue(migratedByAnnotation, "migration-a"))
}

// migratorForKind picks the migrator for a single resource kind out of the
// registry.
func migratorForKind(t *testing.T, ms []migrators.ResourceMigrator, kind string) migrators.ResourceMigrator {
	t.Helper()
	for _, m := range ms {
		if m.Kind() == kind {
			return m
		}
	}
	t.Fatalf("no migrator registered for kind %s", kind)
	return nil
}
